FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY tests/ ./tests/
RUN pip install --no-cache-dir '.[test]'
USER 65534
CMD ["pytest", "-q"]
