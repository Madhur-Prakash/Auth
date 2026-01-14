from kafka import KafkaConsumer
import os
import sys
import asyncio
import json
import traceback
from dotenv import load_dotenv
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, BASE_DIR)
from authentication.helper.utils import setup_logging, create_new_log
from authentication.config.database_config.database import mongo_client

load_dotenv()

DEVELOPMENT_ENV = os.getenv("DEVELOPMENT_ENV", "local")
TOPIC_NAME = "user_signups"
GROUP_ID = "user_signup_worker"
BATCH_SIZE = 2
MAX_RETRIES = 3

BOOTSTRAP_SERVERS = (
    ["kafka:29092"] if DEVELOPMENT_ENV == "docker" else ["localhost:9092"])

logger = setup_logging()

consumer = KafkaConsumer(
    TOPIC_NAME,
    bootstrap_servers=BOOTSTRAP_SERVERS,
    group_id=GROUP_ID,
    auto_offset_reset="earliest",
    enable_auto_commit=False,  # manual commit
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
)

# --------------------------------------------------
# DB INSERT (ASYNC)
# --------------------------------------------------
async def insert_batch(batch: list) -> bool:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            await mongo_client.auth.user.insert_many(batch, ordered=False)
            logger.info(f"✅ Inserted batch of {len(batch)} users")
            create_new_log("info",f"Inserted batch of {len(batch)} users","/api/backend/Auth")
            return True

        except Exception as e:
            logger.error(f"Insert failed (attempt {attempt}): {e}")
            await asyncio.sleep(2)

    formatted_traceback = traceback.format_exc()
    create_new_log("error", formatted_traceback, "/api/backend/Auth")
    return False

# --------------------------------------------------
# KAFKA POLLER (RUNS IN THREAD)
# --------------------------------------------------
def kafka_poller(queue: asyncio.Queue):
    try:
        for message in consumer:
            logger.info(f"📥 Consumed message | partition={message.partition}, offset={message.offset}")
            queue.put_nowait(message.value)
    except Exception as e:
        logger.error(f"Kafka poller error: {e}")
    finally:
        consumer.close()

# --------------------------------------------------
# MAIN ASYNC LOOP
# --------------------------------------------------
async def run_kafka_worker():
    queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    # Run Kafka poller in background thread
    loop.run_in_executor(None, kafka_poller, queue)

    signup_batch = []

    try:
        while True:
            user_data = await queue.get()
            signup_batch.append(user_data)

            if len(signup_batch) >= BATCH_SIZE:
                success = await insert_batch(signup_batch)
                if success:
                    consumer.commit()
                    signup_batch.clear()

    except asyncio.CancelledError:
        logger.warning("Kafka worker cancelled")

    except KeyboardInterrupt:
        logger.info("Shutting down Kafka worker...")

    finally:
        # Flush remaining batch
        if signup_batch:
            logger.info("Flushing remaining batch before shutdown...")
            success = await insert_batch(signup_batch)
            if success:
                logger.info("Final batch inserted successfully")
                consumer.commit()

        consumer.close()
        logger.info("Kafka consumer closed cleanly")

# --------------------------------------------------
# ENTRYPOINT
# --------------------------------------------------
if __name__ == "__main__":
    print("🚀 Kafka signup worker started...")
    asyncio.run(run_kafka_worker())
