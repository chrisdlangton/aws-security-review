FROM python:3.7-slim

RUN adduser --disabled-login --home '/app' aws-user
VOLUME [ "/app" ]
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt

COPY config.yaml /app/config.yaml
COPY rules.yaml /app/rules.yaml
COPY ignores.yaml /app/ignores.yaml

USER aws-user
ENTRYPOINT [ "python" ]
