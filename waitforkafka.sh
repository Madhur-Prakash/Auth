#!/bin/bash
# wait-for-kafka.sh

set -e

host="$1"
port="$2"

until nc -z "$host" "$port"; do
  echo "Waiting for Kafka at $host:$port..."
  sleep 3
done

echo "Kafka is up - executing command"
exec "${@:3}"
