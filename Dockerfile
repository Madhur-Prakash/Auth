    FROM python:3.10-slim

    WORKDIR /authentication

    COPY requirements.txt requirements.txt
    RUN pip install -r requirements.txt
    COPY . .
    EXPOSE 8005
    
    CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8005"]