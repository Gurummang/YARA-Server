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

# 최대 재시도 횟수 설정
MAX_RETRIES = 10


def connect_to_rabbitmq():
    retry_count = 0
    while retry_count < MAX_RETRIES:
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
            retry_count += 1
            logging.error(
                f"Connection failed, retrying ({retry_count}/{MAX_RETRIES}) in {RETRY_INTERVAL} seconds... Error: {e}"
            )
            time.sleep(RETRY_INTERVAL)

    logging.error(f"Failed to connect to RabbitMQ after {MAX_RETRIES} attempts.")
    return None


def start_consuming(queue_name, yara_rules, RoutingKey):
    connection = connect_to_rabbitmq()
    if not connection:
        logging.error("Failed to establish connection to RabbitMQ. Exiting.")
        return

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

            if body is None:
                logging.error("Received None message")
                return

            # 바이트 스트림을 UTF-8 문자열로 변환
            try:
                message_str = body.decode("utf-8")
                logging.info(f"Decoded message: {message_str}")
            except UnicodeDecodeError:
                logging.error(f"Failed to decode message: {body}")
                ch.basic_nack(
                    delivery_tag=method.delivery_tag, requeue=False
                )  # 실패한 메시지 확인 후 재시도 하지 않음
                return

            # 문자열을 정수로 변환 시도 (예: 파일 ID가 숫자로 구성된 문자열인 경우)
            try:
                file_id = int(message_str)
                logging.info(f"Converted file_id: {file_id}")
                # 파일 ID를 사용하여 파일을 스캔
                scan_file(file_id, yara_rules)
                ch.basic_ack(
                    delivery_tag=method.delivery_tag
                )  # 정상 처리 후 메시지 확인
            except ValueError:
                logging.error(f"Failed to convert message to an integer: {message_str}")
                ch.basic_nack(
                    delivery_tag=method.delivery_tag, requeue=True
                )  # 실패한 메시지 다시 큐로 보내기

        except Exception as e:
            logging.error(f"Error processing message: {e}")
            ch.basic_nack(
                delivery_tag=method.delivery_tag, requeue=True
            )  # 예외 발생 시 메시지 재처리
            log_failed_message(queue_name, body)

    # 실패한 메시지 로그 저장
    def log_failed_message(queue_name, body):
        try:
            with open(f"failed_messages_{queue_name}.log", "a") as f:
                f.write(f"Failed message: {body}\n")
            logging.info(f"Logged failed message to failed_messages_{queue_name}.log")
        except Exception as e:
            logging.error(f"Failed to log message: {e}")

    channel.basic_consume(
        queue=queue_name,
        on_message_callback=on_message,
        auto_ack=False,  # auto_ack=False로 설정하여 수동으로 처리
    )
    logging.info(f"Waiting for messages in {queue_name}. To exit press CTRL+C")
    channel.start_consuming()
