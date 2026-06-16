FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask flask-cors requests
COPY app.py .
COPY static/ static/
EXPOSE 7000
CMD ["python", "-u", "app.py"]
