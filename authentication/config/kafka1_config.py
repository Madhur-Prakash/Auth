from kafka import KafkaConsumer
import os
import sys
import asyncio
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import mongo_client  # Use absolute import instead of relative import
import json
from helper.utils import create_new_log, setup_logging
import traceback
import time

# Kafka Consumer
consumer = KafkaConsumer(
    'user_signups',
    bootstrap_servers=['localhost:9092'],
    group_id='user_signup_worker',
    auto_offset_reset='earliest',
    enable_auto_commit=False,  # We'll commit manually after success
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)


logger = setup_logging()


async def insert_batch(batch):
    for attempt in range(3):  # Retry 3 times
        try:
            await mongo_client.auth.user.insert_many(batch, ordered=False)
            print(f"✅ Inserted batch of {len(batch)} users.")
            # Log the successful insert
            logger.info(f"Inserted batch of {len(batch)} users.")
            create_new_log("info", f"Inserted batch of {len(batch)} users.", "/api/backend/Auth")
            return True
        except Exception as e:
            logger.error(f"Failed to insert user data: {e}")
            print(f"⚠️ Insert failed. Retrying... Attempt {attempt+1}")
            time.sleep(2)  # Wait before retry
    print("❌ Insert failed after 3 attempts. Logging error...")
    formatted_traceback = traceback.format_exc()
    create_new_log("error", formatted_traceback, "/api/backend/Auth")
    # (Optional) Save failed data somewhere safe
    return False

print("Worker started, waiting for signup messages...")
async def run_kafka():
    BATCH_SIZE = 2   # Insert 100 users at once
    SIGNUP_BATCH = []  # Temporary storage for batch
    try:
        for message in consumer:
            user_data = message.value
            SIGNUP_BATCH.append(user_data)

            if len(SIGNUP_BATCH) >= BATCH_SIZE:
                success = await insert_batch(SIGNUP_BATCH)
                if success:
                    consumer.commit()  # Only commit Kafka offset after successful DB write
                    SIGNUP_BATCH = []  # Clear batch

    except KeyboardInterrupt:
        print("Shutting down worker...")
    finally:
        consumer.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_kafka())
    loop.close()