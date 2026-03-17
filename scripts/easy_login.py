import argparse
import os
import time
from pathlib import Path
from typing import Any
import requests
import urllib3

from dotenv import load_dotenv

import logging

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("easy_login")

BASE_URL = "https://localhost:3000"
USERNAME = os.getenv("EASY_USERNAME", "admin")
PASSWORD = os.getenv("EASY_PASSWORD", "rpa@2026!")


def run_easy_login(verify_tls: bool) -> dict[str, Any]:
    
    
    if not verify_tls:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    started_at = time.perf_counter()
    
    try:
        session.get(f"{BASE_URL}/easy/", timeout=10, verify=verify_tls)
        response = session.post(
            f"{BASE_URL}/api/easy/login",
            json={"username": USERNAME, "password": PASSWORD},
            timeout=10,
            verify=verify_tls,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro ao acessar a página de login: {e}")
        raise Exception(f"Erro ao acessar a página de login: {e}")
    
    if not payload.get("success"):
        logger.error(f"Erro ao autenticar: {payload.get('message')}")
        raise Exception(f"Erro ao autenticar: {payload.get('message')}")

    local_elapsed_ms = int((time.perf_counter() - started_at) * 1000)
    payload["local_elapsed_ms"] = local_elapsed_ms
    payload["easy_success"] = bool(payload.get("success"))
    payload["final_token"] = payload.get("token")
    payload["total_elapsed_ms"] = local_elapsed_ms
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Executa automacao do nivel facil do RPA Challenge."
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Ativa validacao do certificado TLS (desligado por padrao).",
    )
    args = parser.parse_args()

    result = run_easy_login(verify_tls=args.verify_tls)

    logger.info("=== Easy Challenge ===")
    logger.info(f"success: {result.get('success')}")
    logger.info(f"message: {result.get('message')}")
    logger.info(f"level: {result.get('level')}")
    logger.info(f"token: {result.get('token')}")
    logger.info(f"api_elapsed_ms: {result.get('elapsed_ms')}")
    logger.info(f"local_elapsed_ms: {result.get('local_elapsed_ms')}")
    logger.info("=== Easy Challenge (final) ===")
    logger.info(f"easy_success: {result.get('easy_success')}")
    logger.info(f"final_token: {result.get('final_token')}")
    logger.info(f"elapsed_ms: {result.get('total_elapsed_ms')}")


if __name__ == "__main__":
    main()
