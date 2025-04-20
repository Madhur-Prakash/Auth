from kafka import KafkaConsumer
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import mongo_client  # Use absolute import instead of relative import
import json
import time

# Kafka Consumer
consumer = KafkaConsumer(
    'patient_signups',
    bootstrap_servers=['localhost:9092'],
    group_id='patient_signup_worker',
    auto_offset_reset='earliest',
    enable_auto_commit=True,  # We'll commit manually after success
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

BATCH_SIZE = 2   # Insert 100 patients at once
SIGNUP_BATCH = []  # Temporary storage for batch

def insert_batch(batch):
    for attempt in range(3):  # Retry 3 times
        try:
            mongo_client.auth.patient.insert_many(batch)
            print(f"✅ Inserted batch of {len(batch)} patients.")
            return True
        except Exception as e:
            print(f"⚠️ Insert failed. Retrying... Attempt {attempt+1}")
            time.sleep(2)  # Wait before retry
    print("❌ Insert failed after 3 attempts. Logging error...")
    # (Optional) Save failed data somewhere safe
    return False

print("Worker started, waiting for signup messages...")

for message in consumer:
    patient_data = message.value
    SIGNUP_BATCH.append(patient_data)

    if len(SIGNUP_BATCH) >= BATCH_SIZE:
        success = insert_batch(SIGNUP_BATCH)
        if success:
            consumer.commit()  # Only commit Kafka offset after successful DB write
            SIGNUP_BATCH = []  # Clear batch
