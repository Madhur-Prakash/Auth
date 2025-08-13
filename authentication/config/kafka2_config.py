from kafka import KafkaConsumer
import os
import sys
import asyncio
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import mongo_client  # Use absolute import instead of relative import
import json
import time
import traceback
from helper.utils import create_new_log, setup_logging
from dotenv import load_dotenv

load_dotenv()

# Kafka Consumer
DEVELOPMENT_ENV = os.getenv("DEVELOPMENT_ENV", "local")

if DEVELOPMENT_ENV == "docker":
    consumer_2 = KafkaConsumer(
        'user_UID',
        bootstrap_servers=['kafka:29092'], # try using kafka:29092 and remove command from docker compose
        group_id='user_UID_worker',
        auto_offset_reset='earliest',
        enable_auto_commit=False,  # We'll commit manually after success
        value_deserializer=lambda m: json.loads(m.decode('utf-8'))
    )
else:
    consumer_2 = KafkaConsumer(
        'user_UID',
        bootstrap_servers=['localhost:9092'],
        group_id='user_UID_worker',
        auto_offset_reset='earliest',
        enable_auto_commit=False,  # We'll commit manually after success
        value_deserializer=lambda m: json.loads(m.decode('utf-8'))
    )


logging = setup_logging()


async def insert_batch(batch):
    # Filter only dict-like entries
    batch = [doc for doc in batch if isinstance(doc, dict)]

    for attempt in range(3):
        try:
            if not batch:
                logging.warning("Empty or invalid batch, skipping insert.")
                return True  # or False depending on your logic

            await mongo_client.profile_data.user_profile_data.insert_many(batch, ordered=False)
            await mongo_client.public_profile_data.user.insert_many(batch, ordered=False)
            print(f"✅ Inserted batch of {len(batch)} users UID.")
            # Log the successful insert
            logging.info(f"Inserted batch of {len(batch)} users UID.")
            create_new_log("info", f"Inserted batch of {len(batch)} users UID.", "/api/backend/Auth")
            return True
        except Exception as e:
            print(f"⚠️ Insert failed. Retrying... Attempt {attempt+1}")
            logging.error(f"Failed to insert user data: {e}")
            time.sleep(2)  # Wait before retry
    print("❌ Insert failed after 3 attempts. Logging error...")
    formatted_traceback = traceback.format_exc()
    create_new_log("error", formatted_traceback, "/api/backend/Auth")
    # (Optional) Save failed data somewhere safe
    return False


print("Worker started, waiting for signup...")

# Google Signup Consumer
async def run_kafka():
    user_UID_BATCH_SIZE = 2   # Insert 100 users at once
    user_UID_BATCH = []  # Temporary storage for batch

    try:
        for val in consumer_2:
            user_data = val.value
            user_UID_BATCH.append(user_data)

            if len(user_UID_BATCH) >= user_UID_BATCH_SIZE:
                success = await insert_batch(user_UID_BATCH)
                if success:
                    consumer_2.commit()  # Only commit Kafka offset after successful DB write
                    user_UID_BATCH = []  # Clear batch

    except KeyboardInterrupt:
        print("Shutting down worker...")
    finally:
        consumer_2.close()

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_kafka())
    loop.close()