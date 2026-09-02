from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from telepathiot.session import Session


def _esc(v: Any) -> str:
    return html.escape(str(v))


def render_html(session: Session) -> str:
    data = session.data
    findings = data.get("findings") or []
    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{_esc(f.get('severity'))}</td>"
            f"<td>{_esc(f.get('module'))}</td>"
            f"<td>{_esc(f.get('title'))}</td>"
            f"<td>{_esc(f.get('target'))}</td>"
            f"<td><pre>{_esc(json.dumps({k: v for k, v in f.items() if k not in ('title', 'module', 'severity', 'target')}, indent=2))}</pre></td>"
            "</tr>"
        )
    actions = data.get("actions") or []
    action_rows = []
    for a in actions[-200:]:
        action_rows.append(
            "<tr>"
            f"<td>{_esc(a.get('ts'))}</td>"
            f"<td>{_esc(a.get('module'))}</td>"
            f"<td>{_esc(a.get('action'))}</td>"
            f"<td>{_esc(a.get('target'))}</td>"
            f"<td>{_esc(a.get('ok'))}</td>"
            "</tr>"
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>TelepathIoT session { _esc(data.get('session_id')) }</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; background: #0f1419; color: #e7ecf3; }}
    h1, h2 {{ color: #9ecbff; }}
    .warn {{ border: 1px solid #f5c542; padding: 0.8rem; border-radius: 8px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #2a3544; padding: 0.4rem 0.6rem; vertical-align: top; font-size: 0.9rem; }}
    th {{ background: #1b2430; text-align: left; }}
    pre {{ white-space: pre-wrap; margin: 0; }}
    .muted {{ color: #8b9bb0; }}
  </style>
</head>
<body>
  <h1>TelepathIoT report</h1>
  <p class="warn">Lab-only assessment. Secrets are redacted. Full values live in the gitignored findings file, not this report.</p>
  <p class="muted">session { _esc(data.get('session_id')) } · started { _esc(data.get('started_at')) } · aborted={ _esc(data.get('aborted')) } · connections={ _esc(data.get('connection_attempts')) }</p>
  <h2>Findings ({len(findings)})</h2>
  <table>
    <tr><th>Severity</th><th>Module</th><th>Title</th><th>Target</th><th>Detail</th></tr>
    {''.join(rows) or '<tr><td colspan="5">None yet.</td></tr>'}
  </table>
  <h2>Module results</h2>
  <pre>{_esc(json.dumps(data.get('modules') or dict(), indent=2))}</pre>
  <h2>Action log (last 200)</h2>
  <table>
    <tr><th>Time</th><th>Module</th><th>Action</th><th>Target</th><th>OK</th></tr>
    {''.join(action_rows) or '<tr><td colspan="5">No actions.</td></tr>'}
  </table>
</body>
</html>
"""


def write_report(session: Session, dest: Path) -> Path:
    dest.write_text(render_html(session), encoding="utf-8")
    session.log_action("report", "write", detail={"path": str(dest)})
    return dest
