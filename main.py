import asyncio
import logging
import os
from contextlib import asynccontextmanager
from threading import Thread

import uvicorn
from fastapi import FastAPI

from app import (
    DOC_ROUTING_KEY,
    DOC_SCAN_QUEUE,
    EXE_ROUTING_KEY,
    EXE_SCAN_QUEUE,
    IMG_ROUTING_KEY,
    IMG_SCAN_QUEUE,
)
from app.rabbitmq_consumer import start_consuming
from app.utils import load_yara_rules

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

    try:
        # YARA 규칙을 로드하고 컴파일
        rules["exe"] = load_yara_rules(os.path.join(RULES_DIR, "exe"))
        rules["img"] = load_yara_rules(os.path.join(RULES_DIR, "img"))
        rules["doc"] = load_yara_rules(os.path.join(RULES_DIR, "doc"))
        print("YARA rules loaded and compiled successfully.")
    except Exception as e:
        print(f"Failed to load YARA rules: {e}")
        logging.error(f"Failed to load YARA rules: {e}")

    Thread(
        target=start_consuming, args=(EXE_SCAN_QUEUE, rules["exe"], EXE_ROUTING_KEY)
    ).start()
    Thread(
        target=start_consuming, args=(IMG_SCAN_QUEUE, rules["img"], IMG_ROUTING_KEY)
    ).start()
    Thread(
        target=start_consuming, args=(DOC_SCAN_QUEUE, rules["doc"], DOC_ROUTING_KEY)
    ).start()

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
