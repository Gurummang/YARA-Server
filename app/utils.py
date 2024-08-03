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


def load_yara_rules(rules_dir):
    filepaths = {}
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(".yar"):
                file_path = os.path.join(root, file)
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


def scan_file(file_id: int, yara_rules, chunk_size=1024 * 1024):  # 1MB 청크
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

        matches = []
        while True:
            chunk = file_stream.read(chunk_size)
            if not chunk:
                break
            chunk_matches = yara_rules.match(data=chunk)
            matches.extend(chunk_matches)

        detect = 1 if matches else 0
        detail = (
            "\n".join([str(match) for match in matches]) if matches else "unmatched"
        )

        logging.info(f"result: {matches}")
        logging.info(f"detect: {detect}")
        logging.info(f"detail: {detail}")

        save_scan_result(file_id, detect, detail)
    except Exception as e:
        logging.error(f"Error scanning file: {e}")
        raise HTTPException(status_code=500, detail="Error scanning file")
