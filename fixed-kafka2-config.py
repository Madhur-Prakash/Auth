from kafka import KafkaConsumer
import os
import sys
import asyncio
import json
import time
import traceback
from dotenv import load_dotenv

load_dotenv()

# Fixed Kafka Consumer
DEVELOPMENT_ENV = os.getenv("DEVELOPMENT_ENV", "local")

def create_consumer():
    if DEVELOPMENT_ENV == "docker":
        bootstrap_servers = ['kafka:9092']  # Use your Kafka image port
    else:
        bootstrap_servers = ['localhost:9092']
    
    # Retry connection
    for attempt in range(5):
        try:
            consumer = KafkaConsumer(
                'user_UID',
                bootstrap_servers=bootstrap_servers,
                group_id='user_UID_worker',
                auto_offset_reset='earliest',
                enable_auto_commit=False,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                consumer_timeout_ms=10000
            )
            print(f"✅ Connected to Kafka: {bootstrap_servers}")
            return consumer
        except Exception as e:
            print(f"❌ Connection attempt {attempt + 1} failed: {e}")
            if attempt < 4:
                time.sleep(5)
            else:
                raise

consumer_2 = create_consumer()

async def insert_batch(batch):
    # Your existing insert logic here
    try:
        # Simulate database insert
        print(f"✅ Processing UID batch of {len(batch)} users")
        return True
    except Exception as e:
        print(f"❌ Insert failed: {e}")
        return False

async def run_kafka():
    user_UID_BATCH_SIZE = 2
    user_UID_BATCH = []
    
    print("🔄 UID Worker started, waiting for messages...")
    
    try:
        for message in consumer_2:
            user_data = message.value
            user_UID_BATCH.append(user_data)
            print(f"📨 Received UID message: {user_data}")

            if len(user_UID_BATCH) >= user_UID_BATCH_SIZE:
                success = await insert_batch(user_UID_BATCH)
                if success:
                    consumer_2.commit()
                    user_UID_BATCH = []
                    print("✅ UID Batch processed and committed")

    except KeyboardInterrupt:
        print("🛑 Shutting down UID worker...")
    finally:
        consumer_2.close()

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_kafka())
    loop.close()