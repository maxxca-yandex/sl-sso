FROM python:3.11

WORKDIR /sso

COPY . .

RUN pip install -r requirements.txt && mkdir -p /certs

EXPOSE 443

CMD ["sanic", "app.server:app", "-H", "0.0.0.0", "-p", "8000", "--tls", "/certs"]
