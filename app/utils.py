import logging
import os

import boto3
import mysql.connector
import yara
from fastapi import HTTPException

from app import (
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    MYSQL_DB,
    MYSQL_HOST,
    MYSQL_PASSWORD,
    MYSQL_USER,
    S3_BUCKET_NAME,
)
from app.models import FileScanRequest

s3 = boto3.client("s3")


def compile_yara_rules(directories):
    rule_sources = {}

    # 리스트 형태로 제공된 여러 디렉토리를 순회합니다.
    for directory in directories:
        # 디렉토리 내의 모든 .yar 파일을 찾습니다.
        yara_files = [
            os.path.join(directory, f)
            for f in os.listdir(directory)
            if f.endswith(".yar")
        ]
        for yara_file in yara_files:
            with open(yara_file, "r") as file:
                # 중복된 파일 이름이 있는지 체크하고 파일 내용을 읽습니다.
                if yara_file in rule_sources:
                    continue  # 이미 같은 이름의 파일이 추가된 경우 덮어쓰기를 피합니다.
                rule_sources[yara_file] = file.read()

    # 모든 규칙을 컴파일합니다.
    compiled_rules = yara.compile(sources=rule_sources)
    return compiled_rules


def ensure_utf8_encoding(file_path):
    try:
        with open(file_path, "rb") as f:
            raw_data = f.read()
        raw_data.decode("utf-8")
        logging.info(f"{file_path} is already UTF-8 encoded.")
    except UnicodeDecodeError:
        logging.info(f"{file_path} is not UTF-8 encoded. Converting to UTF-8.")
        with open(file_path, "r", encoding="latin1") as f:
            content = f.read()
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)


def load_yara_rules(rules_dir):
    filepaths = {}
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(".yar"):
                file_path = os.path.join(root, file)
                ensure_utf8_encoding(file_path)
                filepaths[file] = file_path

    if not filepaths:
        logging.error(f"No YARA rules found in directory: {rules_dir}")
        return None

    logging.info(f"Compiling YARA rules from files: {filepaths}")
    try:
        return yara.compile(filepaths=filepaths)
    except yara.Error as e:
        logging.error(f"Error compiling YARA rules: {e}")
        for filepath in filepaths.values():
            logging.error(f"Failed to compile YARA rule file: {filepath}")
        return None


def download_file_from_s3(file_path, s3_key):
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    bucket_name = s3_key.split("/")[0]
    key = "/".join(s3_key.split("/")[1:])

    try:
        # logging.info(
        #     f"Attempting to download file from S3. Bucket: {bucket_name}, Key: {key}, Local Path: {file_path}"
        # )
        s3_client.download_file(bucket_name, key, file_path)
        logging.info(f"File downloaded successfully from S3: {key}")
    except Exception as e:
        logging.error(f"Failed to download file from S3: {e}")
        raise


def save_scan_result(file_id, detect, detail):
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DB
        )
    except Exception as e:
        logging.error(f"Failed to connect to MySQL: {e}")

    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_table (file_id, detect, step2_detail) VALUES (%s, %s, %s)",
        (file_id, detect, detail),
    )
    conn.commit()
    cursor.close()
    conn.close()


def scan_file(file_id: int, yara_rules):
    logging.info(f"rules : {yara_rules}")
    file_path = None  # Initialize file_path here for use in finally block
    try:
        # MySQL에서 파일 정보를 가져옵니다.
        logging.info("Connecting to MySQL database...")
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB,
        )
        cursor = conn.cursor(dictionary=True)
        logging.info(f"Executing query to retrieve file record for file_id: {file_id}")
        cursor.execute("SELECT * FROM stored_file WHERE id = %s", (file_id,))
        file_record = cursor.fetchone()
        cursor.close()
        conn.close()
        logging.info(f"file_record: {file_record}")

        if not file_record:
            logging.error("File not found in database.")
            raise HTTPException(status_code=404, detail="File not found")

        # S3에서 파일을 다운로드합니다.
        download_path = os.path.join(os.path.dirname(__file__), "downloads")
        if not os.path.exists(download_path):
            os.makedirs(download_path)

        file_path = os.path.join(
            download_path, os.path.basename(file_record["save_path"])
        )
        print(file_path)
        s3_key = file_record["save_path"]
        # logging.info(
        #     f"Downloading file from S3 with key: {s3_key} to path: {file_path}"
        # )

        try:
            download_file_from_s3(file_path, s3_key)
        except Exception as e:
            logging.error(f"Failed to download file from S3: {e}")
            raise HTTPException(
                status_code=500, detail="Failed to download file from S3"
            )

        # YARA를 사용하여 파일을 검사합니다.
        logging.info(f"Scanning file at path: {file_path} with YARA rules.")
        target_file_path = os.path.join(download_path, s3_key.split("/")[-1])
        matches = yara_rules.match(target_file_path)
        logging.info(f"Scan result: {matches}")
        detect = 1 if matches else 0
        detail = "\n".join([str(match) for match in matches])
        logging.info(
            f"Scan result for file {file_id}: detect={detect}, detail={detail}"
        )

        # 결과를 MySQL에 저장합니다.
        save_scan_result(file_id, detect, detail)
    except Exception as e:
        logging.error(f"Error scanning file: {e}")
        raise HTTPException(status_code=500, detail="Error scanning file")
    finally:
        # 로컬에 다운로드한 파일을 삭제합니다.
        try:
            if file_path and os.path.exists(file_path):
                logging.info(f"Deleting local file at path: {file_path}")
                os.remove(file_path)
        except Exception as e:
            logging.error(f"Failed to delete local file: {e}")
