import logging
import ssl
import time
import struct
import pika
import aio_pika

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

# SSL 설정
ssl_options = None
if RABBITMQ_SSL_ENABLED:
    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ssl_options = pika.SSLOptions(context=ssl_context)


def connect_to_rabbitmq():
    while True:
        try:
            credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASSWORD)
            parameters = pika.ConnectionParameters(
                host=RABBITMQ_HOST,
                port=int(RABBITMQ_PORT),
                credentials=credentials,
                ssl_options=ssl_options,
                connection_attempts=3,
                retry_delay=5,
                socket_timeout=10.0,  # 타임아웃 설정 (초)
            )
            connection = pika.BlockingConnection(parameters)
            return connection
        except pika.exceptions.AMQPConnectionError as e:
            logging.error(
                f"Connection failed, retrying in {RETRY_INTERVAL} seconds... Error: {e}"
            )
            time.sleep(RETRY_INTERVAL)


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
