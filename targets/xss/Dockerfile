FROM python:3.11-slim
WORKDIR /app
RUN pip install flask --quiet
COPY app.py .
EXPOSE 8082
CMD ["python", "app.py"]