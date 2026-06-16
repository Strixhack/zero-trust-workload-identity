FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask cryptography
COPY app.py .
EXPOSE 8081
CMD ["python", "-u", "app.py"]
