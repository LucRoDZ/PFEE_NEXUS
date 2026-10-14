# One image for every NEXUS service; the command selects the component.
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" httpx cryptography boto3 pydicom numpy
COPY nexus ./nexus
COPY demo ./demo
RUN useradd --uid 10001 --create-home nexus && mkdir -p /data && chown nexus /data
USER 10001
ENV NEXUS_DATA_DIR=/data
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "nexus.hdg.audit:app", "--host", "0.0.0.0", "--port", "8000"]
