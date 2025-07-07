    FROM python:3.10-slim

    WORKDIR /authentication

    COPY requirements.txt requirements.txt
    RUN pip install -r requirements.txt
    EXPOSE 8005
    EXPOSE 9092
    EXPOSE 2181
    COPY . .
    RUN chmod +x run.sh
    RUN ./run.sh
    # RUN cd authentication && cd config && python kafka_consumer.py
    CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8005", "--reload"]