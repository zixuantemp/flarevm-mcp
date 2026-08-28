FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    smbclient curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -e .
COPY server.py ./
COPY flarevm_mcp ./flarevm_mcp
ENTRYPOINT ["python", "server.py"]
