FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin mcp \
 && mkdir -p /data && chown mcp /data
USER mcp
EXPOSE 8765
CMD ["python", "server.py"]
