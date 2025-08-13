#!/bin/sh
# wait-for-kafka.sh

KAFKA_HOST=${KAFKA_HOST:-kafka}
KAFKA_PORT=${KAFKA_PORT:-29092}

echo "⏳ Waiting for Kafka at $KAFKA_HOST:$KAFKA_PORT..."

while ! nc -z "$KAFKA_HOST" "$KAFKA_PORT"; do
  sleep 1
done

echo "✅ Kafka is up and running!"

exec "$@"
