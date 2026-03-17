"""
Nivel extremo do RPA Challenge.

Fluxo: init -> WebSocket (PoW) -> verify-token (decrypt OTP) -> complete.
"""

import argparse
import asyncio
import hashlib
import itertools
import json
import os
import ssl
import time
from pathlib import Path
from typing import Any

import requests
import urllib3

from dotenv import load_dotenv

import logging

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("extreme_login")

BASE_URL = "https://localhost:3000"
WS_URL = "wss://localhost:3000/ws"
USERNAME = os.getenv("EXTREME_USERNAME", "root")
PASSWORD = os.getenv("EXTREME_PASSWORD", "h4ck3r@Pr00f!")
SECRET_SUFFIX = "extreme_secret_key"


def solve_pow(prefix: str, difficulty: int) -> str:
    """Encontra nonce tal que SHA256(prefix+nonce) comece com N zeros."""
    target = "0" * difficulty
    for i in itertools.count():
        logger.debug("Tentativa %d...", i)
        nonce = str(i)
        h = hashlib.sha256((prefix + nonce).encode()).hexdigest()
        if h.startswith(target):
            logger.debug("Nonce encontrado: %s", nonce)
            return nonce
        if i % 500_000 == 0 and i > 0:
            logger.debug("PoW: tentativas %d...", i)
            logger.info("PoW: tentativas %d...", i)


def decrypt_otp(session_id: str, encrypted_payload: str) -> str:
    """Decripta payload AES-256-CBC e extrai OTP."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    key = hashlib.sha256((session_id + SECRET_SUFFIX).encode()).digest()
    iv_hex, cipher_hex = encrypted_payload.split(":", 1)
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(cipher_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plain = unpad(cipher.decrypt(ciphertext), AES.block_size)
    payload = json.loads(plain.decode())
    return payload.get("otp", "")


async def run_websocket_pow(ws_ticket: str, session_id: str) -> str | None:
    """Conecta ao WebSocket, resolve PoW e retorna intermediate_token."""
    import websockets

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    uri = f"{WS_URL}?ticket={ws_ticket}&session_id={session_id}"

    async with websockets.connect(uri, ssl=ssl_ctx, close_timeout=5) as ws:
        msg = await asyncio.wait_for(ws.recv(), timeout=10)
        obj = json.loads(msg)
        if obj.get("type") != "pow_challenge":
            return None
        nonce = solve_pow(obj["prefix"], obj["difficulty"])
        await ws.send(json.dumps({"nonce": nonce}))
        msg = await asyncio.wait_for(ws.recv(), timeout=60)
        obj = json.loads(msg)
        if obj.get("type") == "pow_result":
            return obj.get("intermediate_token")
    return None


def run_extreme_login(verify_tls: bool = False) -> dict[str, Any]:
    """Executa o fluxo completo do nivel extremo."""
    if not verify_tls:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    started_at = time.perf_counter()

    try:
        # 1. GET /extreme/ para sessao
        session.get(f"{BASE_URL}/extreme/", timeout=10, verify=verify_tls)

        # 2. POST /api/extreme/init
        r_init = session.post(
            f"{BASE_URL}/api/extreme/init",
            timeout=10,
            verify=verify_tls,
        )
        r_init.raise_for_status()
        init_data = r_init.json()
        success = init_data.get("success", False)
        if not success:
            message = init_data.get("message", "Init falhou")
            elapsed_ms = int((time.perf_counter() - started_at) * 1000)
            return {
                "extreme_success": success,
                "final_token": None,
                "elapsed_ms": elapsed_ms,
                "message": message,
            }
        session_id = init_data["session_id"]
        ws_ticket = init_data["ws_ticket"]

        # 3. WebSocket: PoW -> intermediate_token
        intermediate_token = asyncio.run(
            run_websocket_pow(ws_ticket, session_id)
        )
        elapsed_ms = int((time.perf_counter() - started_at) * 1000)
        if not intermediate_token:
            message = "Falha ao obter intermediate_token via WebSocket"
            return {
            "extreme_success": False,
            "final_token": None,
            "elapsed_ms": elapsed_ms,
            "message": message,
        }

        # 4. POST /api/extreme/verify-token
        r_verify = session.post(
            f"{BASE_URL}/api/extreme/verify-token",
            json={"session_id": session_id, "intermediate_token": intermediate_token},
            timeout=10,
            verify=verify_tls,
        )
        r_verify.raise_for_status()
        verify_data = r_verify.json()
        message = verify_data.get("message", "Verify-token falhou")
        success = verify_data.get("success", False)
        elapsed_ms = int((time.perf_counter() - started_at) * 1000)
        if not success:
            return {
                "extreme_success": success,
                "final_token": None,
                "elapsed_ms": elapsed_ms,
                "message": message,
            }
        encrypted_payload = verify_data.get("encrypted_payload", "")
        otp = decrypt_otp(session_id, encrypted_payload)

        # 5. POST /api/extreme/complete
        r_complete = session.post(
            f"{BASE_URL}/api/extreme/complete",
            json={
                "session_id": session_id,
                "otp": otp,
                "username": USERNAME,
                "password": PASSWORD,
            },
            timeout=10,
            verify=verify_tls,
        )
        r_complete.raise_for_status()
        complete_data = r_complete.json()
    except requests.exceptions.RequestException as e:
        logger.error("Erro de requisicao: %s", e)
        elapsed_ms = int((time.perf_counter() - started_at) * 1000)
        return {
            "extreme_success": False,
            "final_token": None,
            "elapsed_ms": elapsed_ms,
            "message": str(e),
        }
    except Exception as e:
        logger.error("Erro: %s", e)
        elapsed_ms = int((time.perf_counter() - started_at) * 1000)
        return {
            "extreme_success": False,
            "final_token": None,
            "elapsed_ms": elapsed_ms,
            "message": str(e),
        }

    success = complete_data.get("success", False)
    final_token = complete_data.get("token") or complete_data.get("proof")
    message = complete_data.get("message")
    elapsed_ms = int((time.perf_counter() - started_at) * 1000)
    return {
        "extreme_success": success,
        "final_token": final_token,
        "elapsed_ms": elapsed_ms,
        "message": message,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Executa automacao do nivel extremo do RPA Challenge."
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Ativa validacao do certificado TLS.",
    )
    args = parser.parse_args()

    result = run_extreme_login(verify_tls=args.verify_tls)

    logger.info("=== Extreme Challenge (final) ===")
    logger.info("extreme_success: %s", result.get("extreme_success"))
    logger.info("final_token: %s", result.get("final_token"))
    logger.info("elapsed_ms: %s", result.get("elapsed_ms"))
    if result.get("message"):
        logger.info("message: %s", result["message"])


if __name__ == "__main__":
    main()
