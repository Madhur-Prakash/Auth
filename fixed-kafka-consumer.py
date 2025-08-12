from kafka import KafkaConsumer
import os
import json
import time

# Fixed configuration
DEVELOPMENT_ENV = os.getenv("DEVELOPMENT_ENV", "local")

def get_bootstrap_servers():
    if DEVELOPMENT_ENV == "docker":
        # Try multiple servers in order
        servers = ['kafka:29092', 'kafka:9092']
        for server in servers:
            try:
                # Test connection
                test_consumer = KafkaConsumer(
                    bootstrap_servers=[server],
                    consumer_timeout_ms=5000
                )
                test_consumer.close()
                print(f"✅ Connected to {server}")
                return [server]
            except:
                continue
        raise Exception("No Kafka servers available")
    else:
        return ['localhost:9092']

# Create consumer with retry
def create_consumer(topic, group_id, max_retries=5):
    for attempt in range(max_retries):
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=get_bootstrap_servers(),
                group_id=group_id,
                auto_offset_reset='earliest',
                enable_auto_commit=False,
                value_deserializer=lambda m: json.loads(m.decode('utf-8'))
            )
            print(f"✅ Consumer created for topic: {topic}")
            return consumer
        except Exception as e:
            print(f"❌ Attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(5)
            else:
                raise

# Usage example
if __name__ == "__main__":
    try:
        consumer = create_consumer('user_signups', 'user_signup_worker')
        
        print("🔄 Waiting for messages...")
        for message in consumer:
            try:
                user_data = message.value
                print(f"📨 Received: {user_data}")
                
                # Process your data here
                # await insert_batch([user_data])
                
                # Commit only after successful processing
                consumer.commit()
                
            except Exception as e:
                print(f"❌ Processing error: {e}")
                
    except KeyboardInterrupt:
        print("🛑 Shutting down...")
    finally:
        if 'consumer' in locals():
            consumer.close()