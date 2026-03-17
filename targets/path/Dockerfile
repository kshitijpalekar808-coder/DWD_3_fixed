FROM python:3.11-slim
WORKDIR /app
RUN pip install flask --quiet
COPY app.py .
RUN mkdir -p /app/files
EXPOSE 8085
CMD ["python", "app.py"]