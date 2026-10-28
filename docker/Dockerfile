FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY educhaintrust/ ./educhaintrust/
COPY api/ ./api/
COPY dashboard/ ./dashboard/
RUN pip install --no-cache-dir ".[api,dashboard]"
EXPOSE 8000
CMD ["uvicorn","api.main:app","--host","0.0.0.0","--port","8000"]
