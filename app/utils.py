import asyncio
import logging
import os
import functools
from collections import defaultdict
from datetime import datetime
import pytz

import boto3
import aiomysql
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
from app.rabbitmq_sender import send_message


async def match_multiple_rules(*rule_file_lists):
    all_rule_files = {}
    rule_index = 0

    for rule_files in rule_file_lists:
        for i, rule_file in enumerate(rule_files):
            all_rule_files[str(rule_index + i)] = rule_file
        rule_index += len(rule_files)

    if all_rule_files:
        try:
            compiled_rules = yara.compile(filepaths=all_rule_files)
            return compiled_rules
        except yara.Error as e:
            logging.error(f"Failed to compile merged YARA rules: {e}")
            return None
    else:
        logging.info("No valid YARA rule files found for merging.")
        return None


async def load_yara_rules(directory):
    rule_files = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".yar"):
                rule_files.append(os.path.join(root, file))

    if rule_files:
        valid_rule_files = []
        for rule_file in rule_files:
            try:
                yara.compile(filepath=rule_file)
                valid_rule_files.append(rule_file)
            except yara.Error as e:
                logging.info(f"Failed to compile YARA rule {rule_file}: {e}")

        if valid_rule_files:
            try:
                compiled_rules = yara.compile(filepaths={str(i): rule for i, rule in enumerate(valid_rule_files)})
                logging.info(f"Compiled {len(valid_rule_files)} YARA rules from {directory}")
                return compiled_rules, valid_rule_files
            except yara.Error as e:
                logging.info(f"Failed to compile YARA rules: {e}")
                return None, valid_rule_files
        else:
            logging.info(f"No valid YARA rule files found in {directory}")
            return None, []
    else:
        logging.info(f"No YARA rule files found in {directory}")
        return None, []


async def stream_file_from_s3(s3_key):
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    bucket_name = s3_key.split("/")[0]
    key = "/".join(s3_key.split("/")[1:])

    try:
        loop = asyncio.get_event_loop()
        # functools.partial로 키워드 인자를 전달할 수 있도록 함
        response = await loop.run_in_executor(
            None, functools.partial(s3_client.get_object, Bucket=bucket_name, Key=key)
        )
        return response["Body"]
    except Exception as e:
        logging.error(f"Failed to stream file from S3: {e}")
        raise




async def save_scan_result(uploadId: int, stored_file_id, detect, detail):
    try:
        conn = await aiomysql.connect(
            host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, db=MYSQL_DB
        )
        async with conn.cursor() as cursor:
            try:
                await cursor.execute(
                    "INSERT INTO scan_table (file_id, detect, step2_detail) VALUES (%s, %s, %s) "
                    "ON DUPLICATE KEY UPDATE detect=VALUES(detect), step2_detail=VALUES(step2_detail)",
                    (stored_file_id, detect, detail),
                )
                await conn.commit()

                tz = pytz.timezone('Asia/Seoul')
                seoul_time = datetime.now(tz)
                logging.info(f"uploadId: {uploadId}, complete: {seoul_time.strftime('%Y-%m-%d %H:%M:%S')}")

                await cursor.execute(
                    "UPDATE file_status SET gscan_status = 1 WHERE file_id = %s", (stored_file_id,)
                )
                await conn.commit()

                await send_message(uploadId)
            except Exception as e:
                await conn.rollback()
                logging.error(f"Failed to update file_status: {e}")
                raise
    except Exception as e:
        logging.error(f"Failed to connect to MySQL: {e}")
        raise


def select_keyword(matches):
    keyword_count = defaultdict(int)

    for match in matches:
        if "atk_type" in match.meta:
            atk_type = match.meta["atk_type"]
            keyword_count[atk_type] += 1

    if keyword_count:
        # 가장 많이 매칭된 atk_type 값을 추출
        keywords = str(keyword_count.keys())
        logging.info(f"Most common atk_type: {keywords}")
        return keywords
    else:
        logging.info("No atk_type found in matches")
        return "unmatched"  # None 대신 기본값 반환



async def yara_test_match(file_path, yara_rules):
    loop = asyncio.get_event_loop()
    with open(file_path, "rb") as f:
        file_data = await loop.run_in_executor(None, f.read)

    matches = yara_rules.match(data=file_data)

    detect = 1 if matches else 0
    detail = "\n".join([str(match) for match in matches]) if matches else "unmatched"

    logging.info(f"result: {matches}")
    logging.info(f"detect: {detect}")
    logging.info(f"detail: {detail}")

    return detect, detail


async def scan_file(upload_id: int, yara_rules):
    try:
        # 파일 업로드 정보 가져오기
        file_record = await get_file_upload(upload_id)
        salted_hash = file_record["salted_hash"]

        # 저장된 파일 정보 가져오기
        stored_file_record = await get_stored_file(salted_hash)
        stored_file_id = stored_file_record["id"]
        s3_key = stored_file_record["save_path"]

        file_stream = await stream_file_from_s3(s3_key)

        # S3에서 반환된 file_stream은 이미 bytes 객체입니다.
        file_data = file_stream.read()  # 여기에서 read()는 필요 없음, file_stream 자체가 파일 데이터임

        # YARA 룰 매칭
        matches = yara_rules.match(data=file_data)

        detect = 1 if matches else 0

        most_common_keyword = select_keyword(matches)
        if most_common_keyword is None:
            most_common_keyword = "unmatched"
        detail = (
            "\n".join([str(match) for match in matches]) if matches else "unmatched"
        )

        logging.info(f"result: {matches}")
        logging.info(f"detect: {detect}")
        logging.info(f"detail: {detail}")
        logging.info(f"most_common_keyword: {most_common_keyword}")

        await save_scan_result(upload_id, stored_file_id, detect, most_common_keyword)
    except Exception as e:
        logging.error(f"Error scanning file: {e}")
        raise HTTPException(status_code=500, detail="Error scanning file")



async def get_stored_file(hash: str):
    try:
        conn = await aiomysql.connect(
            host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, db=MYSQL_DB
        )
        async with conn.cursor(aiomysql.DictCursor) as cursor:
            await cursor.execute("SELECT * FROM stored_file WHERE salted_hash = %s", (hash,))
            stored_file_record = await cursor.fetchone()

            if not stored_file_record:
                raise HTTPException(status_code=404, detail="File not found in stored_file table")

            return stored_file_record
    except Exception as e:
        logging.error(f"Error fetching stored file record: {e}")
        raise HTTPException(status_code=500, detail="Error fetching stored file record")


async def get_file_upload(file_id: int):
    try:
        conn = await aiomysql.connect(
            host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, db=MYSQL_DB
        )
        async with conn.cursor(aiomysql.DictCursor) as cursor:
            await cursor.execute("SELECT * FROM file_upload WHERE id = %s", (file_id,))
            file_record = await cursor.fetchone()

            if not file_record:
                raise HTTPException(status_code=404, detail="File not found in file_upload table")

            return file_record
    except Exception as e:
        logging.error(f"Error fetching file upload record: {e}")
        raise HTTPException(status_code=500, detail="Error fetching file upload record")
