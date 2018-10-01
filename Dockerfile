FROM python:2.7-alpine

VOLUME [ "/app" ]
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt

COPY config.yaml /app/config.yaml
COPY rules.yaml /app/rules.yaml

ENTRYPOINT [ "python" ]
CMD [ "src/main.py" ]