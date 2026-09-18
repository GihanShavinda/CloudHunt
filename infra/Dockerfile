FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .
COPY sample_data ./sample_data
COPY scripts ./scripts
EXPOSE 8000
CMD ["uvicorn", "cloudhunt.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
