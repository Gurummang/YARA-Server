import asyncio
import logging
import ssl
from typing import Optional

import aio_pika
from aio_pika import Channel, Connection, IncomingMessage, Queue

from app import (
    EXCHANGE_NAME,
    EXCHANGE_TYPE,
    RABBITMQ_HOST,
    RABBITMQ_PASSWORD,
    RABBITMQ_PORT,
    RABBITMQ_SSL_ENABLED,
    RABBITMQ_USER,
    RETRY_INTERVAL,
)
from app.utils import scan_file

MAX_RETRIES = 10


async def connect_to_rabbitmq() -> Optional[Connection]:
    retry_count = 0
    while retry_count < MAX_RETRIES:
        try:
            ssl_context = None
            if RABBITMQ_SSL_ENABLED:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            connection = await aio_pika.connect_robust(
                host=RABBITMQ_HOST,
                port=int(RABBITMQ_PORT),
                login=RABBITMQ_USER,
                password=RABBITMQ_PASSWORD,
                ssl=ssl_context,
            )
            return connection
        except aio_pika.AMQPConnectionError as e:
            retry_count += 1
            logging.error(
                f"Connection failed, retrying ({retry_count}/{MAX_RETRIES}) in {RETRY_INTERVAL} seconds... Error: {e}"
            )
            await asyncio.sleep(RETRY_INTERVAL)

    logging.error(f"Failed to connect to RabbitMQ after {MAX_RETRIES} attempts.")
    return None


async def on_message(message: IncomingMessage, yara_rules):
    try:
        body = message.body
        logging.info(f"Received message: {body}")

        if not body:
            logging.error("Received empty message")
            await message.nack(requeue=False)  # 재처리 없이 nack
            return

        try:
            message_str = body.decode("utf-8")
            logging.info(f"Decoded message: {message_str}")
        except UnicodeDecodeError:
            logging.error(f"Failed to decode message: {body}")
            await message.nack(requeue=False)  # 재처리 없이 nack
            return

        try:
            file_id = int(message_str)
            logging.info(f"Processing file with ID: {file_id}")
            await scan_file(file_id, yara_rules)
            await message.ack()  # 성공적으로 처리되면 ack
        except ValueError:
            logging.error(f"Invalid file ID format: {message_str}")
            await message.nack(requeue=False)  # 잘못된 파일 ID는 재처리 안 함
    except Exception as e:
        logging.exception(f"Error processing message: {e}")
        await message.nack(requeue=False)  # 예외 발생 시 메시지를 재처리 가능


async def start_consuming(queue_name: str, yara_rules, routing_key: str):
    connection = await connect_to_rabbitmq()
    if not connection:
        logging.error("Failed to establish connection to RabbitMQ. Exiting.")
        return

    try:
        channel: Channel = await connection.channel()
        exchange = await channel.declare_exchange(
            EXCHANGE_NAME, aio_pika.ExchangeType(EXCHANGE_TYPE), durable=True
        )

        queue: Queue = await channel.declare_queue(queue_name, durable=True)
        await queue.bind(exchange, routing_key)

        logging.info(f"Waiting for messages in {queue_name}. To exit press CTRL+C")

        async def shutdown():
            logging.info("Shutting down consumer.")
            await connection.close()

        # 메시지를 처리하는 부분에 shutdown 처리 로직을 추가
        loop = asyncio.get_event_loop()
        try:
            await queue.consume(lambda message: on_message(message, yara_rules))
            await asyncio.Future()  # 무한 대기
        except asyncio.CancelledError:
            await shutdown()
        finally:
            await shutdown()  # 종료 시 RabbitMQ 연결 정리
    except Exception as e:
        logging.exception(f"Error in start_consuming: {e}")

