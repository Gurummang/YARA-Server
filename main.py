import asyncio
import logging
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from app import (
    DOC_ROUTING_KEY,
    DOC_SCAN_QUEUE,
    EXE_ROUTING_KEY,
    EXE_SCAN_QUEUE,
    IMG_ROUTING_KEY,
    IMG_SCAN_QUEUE,
    ALL_SCAN_QUEUE,
    ALL_ROUTING_KEY
)
from app.rabbitmq_consumer import start_consuming
from app.utils import load_yara_rules, match_multiple_rules

app = FastAPI()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 애플리케이션 시작 시 실행할 코드
    RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
    rules = {
        "exe": None,
        "img": None,
        "doc": None,
    }

    exe_files, img_files, doc_files = [], [], []  # 기본값 설정

    try:
        # YARA 규칙을 로드하고 컴파일 (await 추가)
        rules["exe"], exe_files = await load_yara_rules(os.path.join(RULES_DIR, "exe"))
        rules["img"], img_files = await load_yara_rules(os.path.join(RULES_DIR, "img"))
        rules["doc"], doc_files = await load_yara_rules(os.path.join(RULES_DIR, "doc"))
        logging.info("YARA rules loaded and compiled successfully.")
    except Exception as e:
        logging.error(f"Failed to load YARA rules: {e}")

    # 비동기 작업으로 start_consuming을 실행 (await 생략 가능)
    asyncio.create_task(start_consuming(EXE_SCAN_QUEUE, rules["exe"], EXE_ROUTING_KEY))
    asyncio.create_task(start_consuming(IMG_SCAN_QUEUE, rules["img"], IMG_ROUTING_KEY))
    asyncio.create_task(start_consuming(DOC_SCAN_QUEUE, rules["doc"], DOC_ROUTING_KEY))

    # ALL QUEUE에는 모든 규칙 적용
    all_rules_matcher = await match_multiple_rules(doc_files, exe_files, img_files)
    asyncio.create_task(start_consuming(ALL_SCAN_QUEUE, all_rules_matcher, ALL_ROUTING_KEY))

    yield

    # 애플리케이션 종료 시 실행할 코드
    logging.info("Shutting down...")
    await asyncio.sleep(0.5)
    print("Shutting down...")


app.router.lifespan_context = lifespan


@app.get("/")
def read_root():
    return {"Hello": "World"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
