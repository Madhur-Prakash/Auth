from kafka import KafkaConsumer
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import mongo_client  # Use absolute import instead of relative import
import json
from helper.utils import create_new_log, setup_logging
import traceback
import time

# Kafka Consumer
consumer = KafkaConsumer(
    'patient_signups',
    bootstrap_servers=['localhost:9092'],
    group_id='patient_signup_worker',
    auto_offset_reset='earliest',
    enable_auto_commit=False,  # We'll commit manually after success
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)


logger = setup_logging()

BATCH_SIZE = 2   # Insert 100 patients at once
SIGNUP_BATCH = []  # Temporary storage for batch


def insert_batch(batch):
    for attempt in range(3):  # Retry 3 times
        try:
            mongo_client.auth.patient.insert_many(batch, ordered=False)
            print(f"✅ Inserted batch of {len(batch)} patients.")
            # Log the successful insert
            logger.info(f"Inserted batch of {len(batch)} patients.")
            create_new_log("info", f"Inserted batch of {len(batch)} patients.", "/api/backend/Auth")
            return True
        except Exception as e:
            logger.error(f"Failed to insert patient data: {e}")
            print(f"⚠️ Insert failed. Retrying... Attempt {attempt+1}")
            time.sleep(2)  # Wait before retry
    print("❌ Insert failed after 3 attempts. Logging error...")
    formatted_traceback = traceback.format_exc()
    create_new_log("error", formatted_traceback, "/api/backend/Auth")
    # (Optional) Save failed data somewhere safe
    return False

print("Worker started, waiting for signup messages...")

try:
    for message in consumer:
        patient_data = message.value
        SIGNUP_BATCH.append(patient_data)

        if len(SIGNUP_BATCH) >= BATCH_SIZE:
            success = insert_batch(SIGNUP_BATCH)
            if success:
                consumer.commit()  # Only commit Kafka offset after successful DB write
                SIGNUP_BATCH = []  # Clear batch

except KeyboardInterrupt:
    print("Shutting down worker...")
finally:
    consumer.close()


