import logging
import os
from collections import defaultdict

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
)
from app.models import FileScanRequest
from app.rabbitmq_sender import send_message


def load_yara_rules(directory):
    rule_files = []

    # 주어진 디렉토리 내의 모든 YARA 파일 찾기
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".yar"):
                rule_files.append(os.path.join(root, file))

    # YARA 룰 컴파일
    if rule_files:
        valid_rule_files = []
        failed_rule_files = []
        for rule_file in rule_files:
            try:
                yara.compile(filepath=rule_file)
                valid_rule_files.append(rule_file)
            except yara.Error as e:
                failed_rule_files.append(rule_file)
                logging.error(f"Failed to compile YARA rule {rule_file}: {e}")
                logging.error(f"Skipping rule {rule_file}")

        if valid_rule_files:
            try:
                compiled_rules = yara.compile(
                    filepaths={str(i): rule for i, rule in enumerate(valid_rule_files)}
                )
                logging.info(
                    f"Compiled {len(valid_rule_files)} YARA rules from {directory}"
                )
                return compiled_rules
            except yara.Error as e:
                logging.error(f"Failed to compile YARA rules: {e}")
                return None
        else:
            logging.error(f"No valid YARA rule files found in {directory}")
            return None
    else:
        logging.error(f"No YARA rule files found in {directory}")
        return None


def stream_file_from_s3(s3_key):
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    bucket_name = s3_key.split("/")[0]
    key = "/".join(s3_key.split("/")[1:])

    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=key)
        return response["Body"]
    except Exception as e:
        logging.error(f"Failed to stream file from S3: {e}")
        raise


def save_scan_result(uploadId: int, stored_file_id, detect, detail):
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DB
        )
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO scan_table (file_id, detect, step2_detail) VALUES (%s, %s, %s)",
                (stored_file_id, detect, detail),
            )
            conn.commit()  # 첫 번째 쿼리 커밋
        except Exception as e:
            conn.rollback()  # 첫 번째 쿼리 롤백
            logging.error(f"Failed to insert into scan_table: {e}")
            raise  # 예외를 다시 발생시켜 상위 호출자에게 전달

        try:
            cursor.execute(
                "UPDATE file_status SET gscan_status = 1 WHERE file_id = %s",
                (stored_file_id,),
            )
            conn.commit()  # 두 번째 쿼리 커밋
            send_message(uploadId)  # RabbitMQ 전송: Alerts
        except Exception as e:
            conn.rollback()  # 두 번째 쿼리 롤백
            logging.error(f"Failed to update file_status: {e}")
            raise  # 예외를 다시 발생시켜 상위 호출자에게 전달

        cursor.close()  # 커서 닫기

    except Exception as e:
        logging.error(f"Failed to connect to MySQL: {e}")
        raise  # 예외를 다시 발생시켜 상위 호출자에게 전달

    finally:
        if conn.is_connected():
            conn.close()  # 연결 닫기


def select_keyword(matches):
    keyword_count = defaultdict(int)

    for match in matches:
        if "atk_type" in match.meta:
            atk_type = match.meta["atk_type"]
            keyword_count[atk_type] += 1

    # atk_type 목록 추출
    logging.info(f"atk_type list: {keyword_count.keys()}")

    # 가장 많이 매칭된 atk_type 값 추출
    if keyword_count:
        return keyword_count.keys()
    else:
        print("No atk_type found in matches")
        return None


def yara_test_match(file_path, yara_rules):
    with open(file_path, "rb") as f:
        file_data = f.read()

    matches = yara_rules.match(data=file_data)

    detect = 1 if matches else 0
    detail = "\n".join([str(match) for match in matches]) if matches else "unmatched"

    logging.info(f"result: {matches}")
    logging.info(f"detect: {detect}")
    logging.info(f"detail: {detail}")

    return detect, detail


def scan_file(upload_id: int, yara_rules):
    try:
        # 파일 업로드 정보 가져오기
        file_record = get_file_upload(upload_id)
        salted_hash = file_record["salted_hash"]

        # 저장된 파일 정보 가져오기
        stored_file_record = get_stored_file(salted_hash)
        stored_file_id = stored_file_record["id"]
        s3_key = stored_file_record["save_path"]

        file_stream = stream_file_from_s3(s3_key)

        # 파일 전체를 한 번에 읽음
        file_data = file_stream.read()

        # YARA 룰 매칭
        matches = yara_rules.match(data=file_data)

        detect = 1 if matches else 0

        keywordlist = str(select_keyword(matches))
        detail = (
            "\n".join([str(match) for match in matches]) if matches else "unmatched"
        )

        logging.info(f"result: {matches}")
        logging.info(f"detect: {detect}")
        logging.info(f"detail: {detail}")
        logging.info(f"key word list: {keywordlist}")

        save_scan_result(upload_id, stored_file_id, detect, keywordlist)
    except Exception as e:
        logging.error(f"Error scanning file: {e}")
        raise HTTPException(status_code=500, detail="Error scanning file")


def get_stored_file(hash: str):
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DB
        )
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM stored_file WHERE salted_hash = %s", (hash,))
        stored_file_record = cursor.fetchone()
        cursor.close()
        conn.close()

        if not stored_file_record:
            raise HTTPException(
                status_code=404, detail="File not found in stored_file table"
            )

        return stored_file_record

    except Exception as e:
        logging.error(f"Error fetching stored file record: {e}")
        raise HTTPException(status_code=500, detail="Error fetching stored file record")


def get_file_upload(file_id: int):
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DB
        )
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM file_upload WHERE id = %s", (file_id,))
        file_record = cursor.fetchone()
        cursor.close()
        conn.close()

        if not file_record:
            raise HTTPException(
                status_code=404, detail="File not found in file_upload table"
            )

        return file_record

    except Exception as e:
        logging.error(f"Error fetching file upload record: {e}")
        raise HTTPException(status_code=500, detail="Error fetching file upload record")
