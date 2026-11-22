FROM python:3.12-slim
WORKDIR /app
COPY loghunter ./loghunter
ENTRYPOINT ["python", "-m", "loghunter"]
