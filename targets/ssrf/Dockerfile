FROM python:3.11-slim
WORKDIR /app
RUN pip install flask requests --quiet
COPY app.py .
EXPOSE 8084
CMD ["python", "app.py"]