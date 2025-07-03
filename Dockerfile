FROM python:3.10-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir scapy scikit-learn joblib flask requests

ENV LINE_TOKEN=""
ENV SLACK_WEBHOOK=""

EXPOSE 5000

CMD ["python", "ids.py", "--mode", "live", "--web"]
