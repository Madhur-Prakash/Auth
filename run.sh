#!/bin/bash

# Wait for Kafka to be ready before starting
echo "Waiting for Kafka to be ready..."
until nc -z kafka 9092; do
  echo "Kafka is not available yet - sleeping"
  sleep 2
done
echo "Kafka is up - starting consumer"

# Start the consumer in the background
cd authentication/config
echo "Running authentication/config/kafka_consumer.py"
python kafka_consumer.py &

# Give it a moment to initialize
sleep 2

# Start the FastAPI application
cd ../..
echo "Starting FastAPI app"
exec uvicorn app:app --host 0.0.0.0 --port 8005 --reload