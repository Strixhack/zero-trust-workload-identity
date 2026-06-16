FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask requests cryptography urllib3
COPY app.py .
EXPOSE 8080 8443
CMD ["python", "-u", "app.py"]
