import logging
import ssl
import time
import struct
import pika

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


def send_message(message: int):
    connection = connect_to_rabbitmq()
    channel = connection.channel()

    # Exchange 선언
    channel.exchange_declare(
        exchange=ALERT_EXCHANGE_NAME, exchange_type=EXCHANGE_TYPE, durable=True
    )

    # int 메시지를 바이트로 변환
    message_bytes = struct.pack('!Q', message)  # '!Q'는 unsigned long long 형식입니다.

    channel.basic_publish(
        exchange=ALERT_EXCHANGE_NAME,
        routing_key=ALERT_ROUTING_KEY,  # 적절한 라우팅 키로 변경
        body=message_bytes,
        properties=pika.BasicProperties(
            delivery_mode=2  # 메시지 영속화
        )
    )

    print(f"Sent message: {message}")
    connection.close()
