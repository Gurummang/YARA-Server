import logging
import ssl
import time

import pika

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


def start_consuming(queue_name, yara_rules, RoutingKey):
    connection = connect_to_rabbitmq()
    channel = connection.channel()

    # Exchange 선언
    channel.exchange_declare(
        exchange=EXCHANGE_NAME, exchange_type=EXCHANGE_TYPE, durable=True
    )

    # Queue 선언
    channel.queue_declare(queue=queue_name, durable=True)

    # Queue를 Exchange에 바인딩
    channel.queue_bind(exchange=EXCHANGE_NAME, queue=queue_name, routing_key=RoutingKey)

    def on_message(ch, method, properties, body):
        try:
            logging.info(f"QUEUE: {queue_name}")
            logging.info(f"Received message: {body}")

            # UTF-8로 디코딩하지 않고, 바로 Long 타입으로 변환 시도
            if body is None:
                logging.error("Received None message")
                return

            # 메시지가 바이트 스트림으로 들어온다고 가정하고 변환 시도
            file_id = int.from_bytes(
                body, byteorder="big", signed=False
            )  # 바이트를 정수로 변환
            logging.info(f"Converted file_id: {file_id}")

            scan_file(file_id, yara_rules)

        except Exception as e:
            logging.error(f"Error processing message: {e}")

    channel.basic_consume(
        queue=queue_name, on_message_callback=on_message, auto_ack=True
    )
    logging.info(f"Waiting for messages in {queue_name}. To exit press CTRL+C")
    channel.start_consuming()
