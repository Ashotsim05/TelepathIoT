from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from telepathiot.constants import DEFAULT_RATE_LIMIT_MS, INTRUSIVE_MODULES
from telepathiot.interrupt import KillSwitch
from telepathiot.isolation import IsolationError, assert_isolated
from telepathiot.modules.acl import run_acl
from telepathiot.modules.bruteforce import run_bruteforce
from telepathiot.modules.fuzz import run_fuzz
from telepathiot.modules.recon import run_recon
from telepathiot.modules.report import write_report
from telepathiot.modules.tls import run_tls
from telepathiot.modules.topics import run_topics
from telepathiot.scope import ScopeError, load_scope
from telepathiot.secrets import FindingsStore
from telepathiot.session import Session


def _confirm(module: str, target: str, *, noninteractive: bool) -> None:
    if module not in INTRUSIVE_MODULES:
        return
    if noninteractive:
        return
    prompt = f"INTRUSIVE module {module!r} against {target}. Type 'go' to proceed: "
    if sys.stdin.isatty():
        got = input(prompt).strip().lower()
        if got != "go":
            raise SystemExit("Human gate: aborted.")
        return
    raise SystemExit(
        "Intrusive module requires a TTY confirmation or --i-confirm-intrusive "
        "(lab automation only)."
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="telepathiot",
        description="Isolated-lab MQTT assessment. Contacts only scope.json allowlisted targets.",
    )
    p.add_argument("--scope", default="scope.json", help="Path to scope.json allowlist")
    p.add_argument("--workdir", default=".", help="Where sessions/ and .findings.json are stored")
    p.add_argument("--skip-isolation-check", action="store_true", help="Do not docker-network-inspect (not recommended)")
    p.add_argument("--i-confirm-intrusive", action="store_true", help="Non-interactive lab confirm for intrusive modules")
    p.add_argument("--rate-limit-ms", type=int, default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_target(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--target", required=True, help="Scope label or hostname")
        sp.add_argument("--port", type=int, default=None)

    r = sub.add_parser("recon", help="Port, protocol, anonymous, $SYS, fingerprint")
    add_target(r)
    r.add_argument("--listen-s", type=float, default=2.0)

    t = sub.add_parser("topics", help="Wildcard discovery + retained/sensitive flagging")
    add_target(t)
    t.add_argument("--username")
    t.add_argument("--password")
    t.add_argument("--listen-s", type=float, default=4.0)

    b = sub.add_parser("bruteforce", help="Rate-limited CONNECT username/password (intrusive)")
    add_target(b)
    b.add_argument("--users", required=True)
    b.add_argument("--passwords", required=True)
    b.add_argument("--protocol", choices=("mqtt311", "mqtt5"), default="mqtt311")

    a = sub.add_parser("acl", help="Pub/sub boundary map (intrusive)")
    add_target(a)
    a.add_argument("--username", required=True)
    a.add_argument("--password", required=True)

    tl = sub.add_parser("tls", help="Cert validation, ciphers, plaintext-beside-TLS")
    add_target(tl)
    tl.add_argument("--plaintext-port", type=int, default=None)

    f = sub.add_parser("fuzz", help="Conservative malformed packets on a disposable broker (intrusive)")
    add_target(f)
    f.add_argument("--qos2-exhaustion", action="store_true", help="Opt-in partial QoS2 handshake test")

    rp = sub.add_parser("report", help="Write HTML report from the current/latest session")
    rp.add_argument("--out", default="sessions/report.html")
    rp.add_argument("--session-id", default=None)

    v = sub.add_parser("verify-env", help="Inspect Docker lab network isolation")
    v.add_argument("--network", default=None)

    s = sub.add_parser("snapshot", help="Copy broker data dirs for rule-4 restore")
    s.add_argument("--lab-dir", default="lab")
    s.add_argument("--name", required=True)

    rs = sub.add_parser("restore", help="Restore broker data dirs from a snapshot")
    rs.add_argument("--lab-dir", default="lab")
    rs.add_argument("--name", required=True)

    return p


def _prepare(args: argparse.Namespace) -> tuple:
    workdir = Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    scope = load_scope(Path(args.scope))
    if scope.require_isolated_network and not args.skip_isolation_check:
        try:
            assert_isolated(scope.docker_network_name)
        except IsolationError as exc:
            raise SystemExit(f"Isolation check failed: {exc}") from exc
    session = Session(workdir)
    session.set_connection_cap(scope.session_connection_cap)
    KillSwitch(session).install()
    findings = FindingsStore(workdir)
    rate = args.rate_limit_ms if args.rate_limit_ms is not None else scope.default_rate_limit_ms
    if rate is None:
        rate = DEFAULT_RATE_LIMIT_MS
    session.log_action(
        "runtime",
        "session_start",
        detail={"scope": str(scope.path), "rate_limit_ms": rate},
    )
    return scope, session, findings, rate


def _snapshot_dirs(lab_dir: Path) -> list[Path]:
    brokers = lab_dir / "brokers"
    dirs = []
    if brokers.exists():
        for child in brokers.iterdir():
            data = child / "data"
            if data.is_dir():
                dirs.append(data)
    return dirs


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "verify-env":
            scope = load_scope(Path(args.scope))
            name = args.network or scope.docker_network_name
            info = assert_isolated(name)
            print(f"OK: {name} Internal={info.get('Internal')} Id={info.get('Id', '')[:12]}")
            return 0

        if args.cmd in {"snapshot", "restore"}:
            lab = Path(args.lab_dir)
            snap = lab / "snapshots" / args.name
            if args.cmd == "snapshot":
                snap.mkdir(parents=True, exist_ok=True)
                for data in _snapshot_dirs(lab):
                    dest = snap / data.parent.name
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(data, dest)
                print(f"Snapshot written to {snap}")
            else:
                if not snap.exists():
                    raise SystemExit(f"No snapshot {snap}")
                for child in snap.iterdir():
                    dest = lab / "brokers" / child.name / "data"
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(child, dest)
                print(f"Restored snapshot {args.name}")
            return 0

        scope, session, findings, rate = _prepare(args)
        workdir = Path(args.workdir).resolve()

        if args.cmd == "report":
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            if args.session_id:
                session = Session(workdir, session_id=args.session_id)
                if session.path.exists():
                    import json as _json

                    session.data = _json.loads(session.path.read_text(encoding="utf-8"))
            else:
                sessions = sorted(
                    (workdir / "sessions").glob("*.session.json"),
                    key=lambda p: p.stat().st_mtime,
                )
                if sessions:
                    import json as _json

                    sid = sessions[-1].name.split(".")[0]
                    session = Session(workdir, session_id=sid)
                    session.data = _json.loads(sessions[-1].read_text(encoding="utf-8"))
            write_report(session, out)
            print(out)
            return 0

        target = scope.require_label_or_host(args.target, args.port)
        _confirm(args.cmd, target.key, noninteractive=args.i_confirm_intrusive)

        if args.cmd == "recon":
            result = run_recon(target, session, listen_s=args.listen_s)
        elif args.cmd == "topics":
            result = run_topics(
                target,
                session,
                findings,
                username=args.username,
                password=args.password,
                listen_s=args.listen_s,
            )
        elif args.cmd == "bruteforce":
            recon_mod = session.data.get("modules", {}).get("recon")
            result = run_bruteforce(
                target,
                session,
                findings,
                users_file=Path(args.users),
                passwords_file=Path(args.passwords),
                rate_limit_ms=rate,
                recon_hint=recon_mod,
                protocol=args.protocol,
            )
        elif args.cmd == "acl":
            result = run_acl(
                target,
                session,
                username=args.username,
                password=args.password,
                rate_limit_ms=rate,
            )
        elif args.cmd == "tls":
            result = run_tls(target, session, scope, plaintext_port=args.plaintext_port)
        elif args.cmd == "fuzz":
            result = run_fuzz(
                target,
                session,
                rate_limit_ms=rate,
                qos2_exhaustion=args.qos2_exhaustion,
            )
        else:
            raise SystemExit(f"unknown command {args.cmd}")

        print(f"session={session.path}")
        print(f"findings_store={findings.path} (gitignored; secrets not printed)")
        import json

        print(json.dumps(result, indent=2, default=str))
        return 0
    except ScopeError as exc:
        print(f"SCOPE DENY: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
