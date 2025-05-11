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

# Kafka Consumer
consumer_2 = KafkaConsumer(
    'patient_google_signups',
    bootstrap_servers=['localhost:9092'],
    group_id='patient_google_signup_worker',    
    auto_offset_reset='earliest',
    enable_auto_commit=False,  # We'll commit manually after success
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)


logging = setup_logging()


async def insert_batch(batch):
    for attempt in range(3):  # Retry 3 times
        try:
            await mongo_client.auth.patient.insert_many(batch, ordered=False)
            print(f"✅ Inserted batch of {len(batch)} patients.")
            # Log the successful insert
            logging.info(f"Inserted batch of {len(batch)} patients.")
            create_new_log("info", f"Inserted batch of {len(batch)} patients.", "/api/backend/Auth")
            return True
        except Exception as e:
            print(f"⚠️ Insert failed. Retrying... Attempt {attempt+1}")
            logging.error(f"Failed to insert patient data: {e}")
            time.sleep(2)  # Wait before retry
    print("❌ Insert failed after 3 attempts. Logging error...")
    formatted_traceback = traceback.format_exc()
    create_new_log("error", formatted_traceback, "/api/backend/Auth")
    # (Optional) Save failed data somewhere safe
    return False


print("Worker started, waiting for connection requests...")

# Google Signup Consumer
async def run_kafka():
    GOOGLE_BATCH_SIZE = 2   # Insert 100 patients at once
    GOOGLE_SIGNUP_BATCH = []  # Temporary storage for batch

    try:
        for val in consumer_2:
            patient_data = val.value
            GOOGLE_SIGNUP_BATCH.append(patient_data)

            if len(GOOGLE_SIGNUP_BATCH) >= GOOGLE_BATCH_SIZE:
                success = await insert_batch(GOOGLE_SIGNUP_BATCH)
                if success:
                    consumer_2.commit()  # Only commit Kafka offset after successful DB write
                    GOOGLE_SIGNUP_BATCH = []  # Clear batch

    except KeyboardInterrupt:
        print("Shutting down worker...")
    finally:
        consumer_2.close()

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_kafka())
    loop.close()