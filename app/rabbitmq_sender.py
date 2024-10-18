import logging
import ssl
import struct
import pika
import aio_pika
import asyncio

from app import (
    ALERT_EXCHANGE_NAME,
    ALERT_ROUTING_KEY,
    EXCHANGE_TYPE,
    RABBITMQ_HOST,
    RABBITMQ_PASSWORD,
    RABBITMQ_PORT,
    RABBITMQ_SSL_ENABLED,
    RABBITMQ_USER,
    RETRY_INTERVAL,
)
MAX_RETRIES = 10

# SSL 설정
ssl_options = None
if RABBITMQ_SSL_ENABLED:
    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ssl_options = pika.SSLOptions(context=ssl_context)


async def connect_to_rabbitmq():
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
                loop=asyncio.get_event_loop()  # asyncio 이벤트 루프 사용
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


async def send_message(message: int):
    connection = await connect_to_rabbitmq()
    if not connection:
        logging.error("Failed to establish connection to RabbitMQ.")
        return

    async with connection:
        channel = await connection.channel()

        # Exchange 선언
        exchange = await channel.declare_exchange(
            ALERT_EXCHANGE_NAME, aio_pika.ExchangeType(EXCHANGE_TYPE), durable=True
        )

        # int 메시지를 바이트로 변환
        message_bytes = struct.pack('!Q', message)  # '!Q'는 unsigned long long 형식입니다.

        await exchange.publish(
            aio_pika.Message(
                body=message_bytes,
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT
            ),
            routing_key=ALERT_ROUTING_KEY
        )

        logging.info(f"Sent message: {message}")
    # connection.close()
