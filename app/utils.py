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
        for rule_file in rule_files:
            try:
                yara.compile(filepath=rule_file)
                valid_rule_files.append(rule_file)
            except yara.Error as e:
                logging.error(f"Failed to compile YARA rule {rule_file}: {e}")

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


def save_scan_result(file_id, detect, detail):
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DB
        )
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO scan_table (file_id, detect, step2_detail) VALUES (%s, %s, %s)",
                (file_id, detect, detail),
            )
            conn.commit()  # 첫 번째 쿼리 커밋
        except Exception as e:
            conn.rollback()  # 첫 번째 쿼리 롤백
            logging.error(f"Failed to insert into scan_table: {e}")
            raise  # 예외를 다시 발생시켜 상위 호출자에게 전달

        try:
            cursor.execute(
                "UPDATE file_status SET gscan_status = 1 WHERE file_id = %s", (file_id,)
            )
            conn.commit()  # 두 번째 쿼리 커밋
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

    # 가장 많이 매칭된 atk_type 값 추출
    if keyword_count:
        most_common_keyword = max(keyword_count, key=keyword_count.get)
        print(f"Most common atk_type: {most_common_keyword}")
        return most_common_keyword
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


def scan_file(file_id: int, yara_rules):
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DB
        )
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM stored_file WHERE id = %s", (file_id,))
        file_record = cursor.fetchone()
        cursor.close()
        conn.close()

        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")

        s3_key = file_record["save_path"]
        file_stream = stream_file_from_s3(s3_key)

        # 파일 전체를 한 번에 읽음
        file_data = file_stream.read()

        # YARA 룰 매칭
        matches = yara_rules.match(data=file_data)

        detect = 1 if matches else 0

        most_common_keyword = select_keyword(matches)
        detail = (
            "\n".join([str(match) for match in matches]) if matches else "unmatched"
        )

        logging.info(f"result: {matches}")
        logging.info(f"detect: {detect}")
        logging.info(f"detail: {detail}")
        logging.info(f"most_common_keyword: {most_common_keyword}")

        save_scan_result(file_id, detect, most_common_keyword)
    except Exception as e:
        logging.error(f"Error scanning file: {e}")
        raise HTTPException(status_code=500, detail="Error scanning file")
