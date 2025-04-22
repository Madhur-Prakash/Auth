from aiokafka import AIOKafkaConsumer
import os
import asyncio
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import mongo_client  # Use absolute import instead of relative import
import json
import time


async def insert_batch(batch):
    for attempt in range(3):
        try:
            await mongo_client.auth.patient.insert_many(batch, ordered=False)
            print(f"✅ Inserted batch of {len(batch)} patients.")
            return True
        except Exception as e:
            print(f"⚠️ Insert failed. Retrying... Attempt {attempt+1} Error: {str(e)}")
            await asyncio.sleep(2)
    print("❌ Insert failed after 3 attempts. Logging error...")
    return False

print("Worker started, waiting for signup messages...")


async def consumer_1():
    consumer = AIOKafkaConsumer(
    'patient_signups',
    bootstrap_servers=['localhost:9092'],
    group_id='patient_signup_worker',
    auto_offset_reset='earliest',
    enable_auto_commit=False,  # We'll commit manually after success
    value_deserializer=lambda m: json.loads(m.decode('utf-8')))
    BATCH_SIZE = 2   # Insert 100 patients at once
    SIGNUP_BATCH = []  # Temporary storage for batch

    await consumer.start()
    
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
       await consumer.stop()


# Google Signup Consumer
async def consumer_2():
    consumer_2 = AIOKafkaConsumer(
    'patient_google_signups',
    bootstrap_servers=['localhost:9092'],
    group_id='patient_google_signup_worker',    
    auto_offset_reset='earliest',
    enable_auto_commit=False,  # We'll commit manually after success
    value_deserializer=lambda m: json.loads(m.decode('utf-8')))
    GOOGLE_BATCH_SIZE = 2   # Insert 100 patients at once
    GOOGLE_SIGNUP_BATCH = []  # Temporary storage for batch

    await consumer_2.start()

    try:
        for val in consumer_2:
            patient_data = val.value
            GOOGLE_SIGNUP_BATCH.append(patient_data)

            if len(GOOGLE_SIGNUP_BATCH) >= GOOGLE_BATCH_SIZE:
                success = insert_batch(GOOGLE_SIGNUP_BATCH)
                if success:
                    consumer_2.commit()  # Only commit Kafka offset after successful DB write
                    GOOGLE_SIGNUP_BATCH = []  # Clear batch

    except KeyboardInterrupt:
        print("Shutting down worker...")
    finally:
       await consumer_2.stop()

    
async def main():
    await asyncio.gather(consumer_1(), consumer_2())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    
    except KeyboardInterrupt:
        print("Shutting down worker...")
