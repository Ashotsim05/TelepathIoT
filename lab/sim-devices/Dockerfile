FROM python:3.12-alpine
WORKDIR /app
RUN pip install --no-cache-dir paho-mqtt==2.1.0
COPY publisher.py /app/publisher.py
CMD ["python", "/app/publisher.py"]
