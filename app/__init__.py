import logging
import os

from dotenv import load_dotenv

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 환경 변수 로드
dotenv_path = os.path.join(os.path.dirname(__file__), "..", ".env")
load_dotenv(dotenv_path)

# 환경 변수 설정
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_DB = os.getenv("MYSQL_DB")
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

# RabbitMQ 설정
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT"))
RETRY_INTERVAL = 5
RABBITMQ_USER = os.getenv("RABBITMQ_USER")
RABBITMQ_PASSWORD = os.getenv("RABBITMQ_PASSWORD")
RABBITMQ_SSL_ENABLED = os.getenv("RABBITMQ_SSL_ENABLED", "true").lower() in (
    "true",
    "1",
    "t",
)

# Exchange 설정
EXCHANGE_NAME = os.getenv("RABBITMQ_EXCHANGE_NAME")
EXCHANGE_TYPE = os.getenv("RABBITMQ_EXCHANGE_TYPE")

# Queue 설정
DOC_SCAN_QUEUE = os.getenv("RABBITMQ_DOC_QUEUE_NAME")
EXE_SCAN_QUEUE = os.getenv("RABBITMQ_EXE_QUEUE_NAME")
IMG_SCAN_QUEUE = os.getenv("RABBITMQ_IMG_QUEUE_NAME")

# Routing Key 설정
EXE_ROUTING_KEY = os.getenv("RABBITMQ_EXE_ROUTING_KEY")
IMG_ROUTING_KEY = os.getenv("RABBITMQ_IMG_ROUTING_KEY")
DOC_ROUTING_KEY = os.getenv("RABBITMQ_DOC_ROUTING_KEY")

# S3
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
# 패키지 초기화 로깅
logger.info("Initialized app package with environment variables loaded.")
