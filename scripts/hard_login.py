import argparse
import hashlib
import os
import secrets
import string
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests
import urllib3

from dotenv import load_dotenv

import logging

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("hard_login")

BASE_URL = "https://localhost:3000"
USERNAME = os.getenv("HARD_USERNAME", "operator")
PASSWORD = os.getenv("HARD_PASSWORD", "cert#Secure2026")
DEFAULT_PFX_PASSWORD = os.getenv("PFX_PASSWORD", "test123")
CHALLENGE_SECRET = "rpa_hard_challenge_2026"
BASE36_ALPHABET = string.ascii_lowercase + string.digits

def extract_token_from_redirect(redirect_url: str | None) -> str | None:
    if not redirect_url:
        return None
    parsed = urlparse(redirect_url)
    token = parse_qs(parsed.query).get("token")
    return token[0] if token else None


def mtls_html_indicates_success(body: Any) -> bool:
    if not isinstance(body, str):
        return False
    body_lower = body.lower()
    return "autentica" in body_lower and "completa" in body_lower


def generate_challenge_payload() -> dict[str, str]:
    """Replica a logica do frontend JS para gerar challenge/timestamp/nonce."""
    timestamp = str(int(time.time() * 1000))
    nonce = "".join(secrets.choice(BASE36_ALPHABET) for _ in range(16))
    raw = f"{timestamp}{nonce}{CHALLENGE_SECRET}".encode("utf-8")
    challenge = hashlib.sha256(raw).hexdigest()
    return {"challenge": challenge, "timestamp": timestamp, "nonce": nonce}


def resolve_verify_value(ca_cert: str | None) -> bool | str:
    if ca_cert:
        return ca_cert
    return False


def run_hard_login(
    ca_cert: str | None,
    client_cert: str | None,
    client_key: str | None,
    client_pfx: str | None,
    pfx_password: str,
) -> dict[str, Any]:

    verify_value = resolve_verify_value(ca_cert=ca_cert)
    if not verify_value:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    started_at = time.perf_counter()
    try:
        # Inicia sessao e cookies no frontend hard.
        session.get(f"{BASE_URL}/hard/", timeout=10, verify=verify_value)
        challenge_fields = generate_challenge_payload()
        payload = {
            "username": USERNAME,
            "password": PASSWORD,
            **challenge_fields,
        }
        login_res = session.post(
            f"{BASE_URL}/api/hard/login",
            json=payload,
            timeout=10,
            verify=verify_value,
        )
        login_res.raise_for_status()
        login_data = login_res.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro ao acessar a página de login: {e}")
        raise Exception(f"Erro ao acessar a página de login: {e}")

    if not login_data.get("success"):
        logger.error(f"Erro ao autenticar: {login_data.get('message')}")
        raise Exception(f"Erro ao autenticar: {login_data.get('message')}")

    local_elapsed_ms = int((time.perf_counter() - started_at) * 1000)
    final_token = extract_token_from_redirect(login_data.get("redirect"))
    result: dict[str, Any] = {
        "hard_login_response": login_data,
        "challenge_payload": challenge_fields,
        "local_elapsed_ms": local_elapsed_ms,
        "final_token": final_token,
        "hard_success": False,
    }
    # Etapa mTLS: segue redirect com certificado de cliente.
    redirect_url = login_data.get("redirect")
    if redirect_url and client_pfx:
        try:
            from requests_pkcs12 import Pkcs12Adapter
        except ImportError as exc:
            raise RuntimeError(
                "Para usar --client-pfx, instale requests-pkcs12: pip install requests-pkcs12"
            ) from exc
        mtls_session = requests.Session()
        mtls_session.cookies.update(session.cookies)
        adapter = Pkcs12Adapter(
            pkcs12_filename=client_pfx,
            pkcs12_password=pfx_password,
        )
        mtls_session.mount(
            "https://",
            adapter,
        )
        mtls_res = mtls_session.get(
            redirect_url,
            timeout=15,
            verify=verify_value,
        )
        mtls_content_type = mtls_res.headers.get("content-type", "")
        mtls_body: Any
        if "application/json" in mtls_content_type:
            mtls_body = mtls_res.json()
        else:
            mtls_body = mtls_res.text[:500]

        result["mtls_response"] = {
            "status_code": mtls_res.status_code,
            "content_type": mtls_content_type,
            "body": mtls_body,
        }
    elif redirect_url and client_cert and client_key:
        cert_tuple = (client_cert, client_key)
        mtls_res = session.get(
            redirect_url,
            timeout=15,
            verify=verify_value,
            cert=cert_tuple,
        )
        mtls_content_type = mtls_res.headers.get("content-type", "")
        mtls_body: Any
        if "application/json" in mtls_content_type:
            mtls_body = mtls_res.json()
        else:
            mtls_body = mtls_res.text[:500]

        result["mtls_response"] = {
            "status_code": mtls_res.status_code,
            "content_type": mtls_content_type,
            "body": mtls_body,
        }
    elif redirect_url:
        result["mtls_response"] = (
            "Redirect recebido, mas mTLS nao executado. "
            "Informe --client-pfx ou --client-cert e --client-key."
        )

    login_ok = bool(login_data.get("success"))
    mtls_ok = False
    mtls_data = result.get("mtls_response")
    if isinstance(mtls_data, dict):
        mtls_ok = mtls_data.get("status_code") == 200 and mtls_html_indicates_success(
            mtls_data.get("body")
        )
    result["hard_success"] = login_ok and mtls_ok
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Executa automacao do nivel dificil (challenge + mTLS)."
    )
    parser.add_argument(
        "--ca-cert",
        default=None,
        help="Caminho para CA (ex.: ca.crt). Se informado, valida o TLS.",
    )
    parser.add_argument(
        "--client-cert",
        default=None,
        help="Caminho do certificado de cliente PEM/CRT para mTLS.",
    )
    parser.add_argument(
        "--client-key",
        default=None,
        help="Caminho da chave privada PEM/KEY para mTLS.",
    )
    parser.add_argument(
        "--client-pfx",
        default=None,
        help="Caminho do certificado PFX para mTLS (ex.: client.pfx).",
    )
    parser.add_argument(
        "--pfx-password",
        default=DEFAULT_PFX_PASSWORD,
        help="Senha do arquivo PFX (padrao: env PFX_PASSWORD).",
    )
    args = parser.parse_args()

    if bool(args.client_cert) != bool(args.client_key):
        logger.error("Use --client-cert e --client-key juntos.")
        raise SystemExit(2)
    if args.client_pfx and (args.client_cert or args.client_key):
        logger.error("Use apenas uma estrategia: --client-pfx OU --client-cert/--client-key.")
        raise SystemExit(2)

    result = run_hard_login(
        ca_cert=args.ca_cert,
        client_cert=args.client_cert,
        client_key=args.client_key,
        client_pfx=args.client_pfx,
        pfx_password=args.pfx_password,
    )

    login = result["hard_login_response"]
    logger.info("=== Hard Challenge (step 1) ===")
    logger.info(f"success: {login.get('success')}")
    logger.info(f"message: {login.get('message')}")
    logger.info(f"ttl_seconds: {login.get('ttl_seconds')}")
    logger.info(f"redirect: {login.get('redirect')}")
    logger.info(f"local_elapsed_ms: {result.get('local_elapsed_ms')}")
    logger.info(f"challenge: {result['challenge_payload']['challenge']}")
    logger.info(f"timestamp: {result['challenge_payload']['timestamp']}")
    logger.info(f"nonce: {result['challenge_payload']['nonce']}")

    if "mtls_response" in result:
        logger.info("=== Hard Challenge (step 2 - mTLS) ===")
        logger.info(str(result["mtls_response"]))

    logger.info("=== Hard Challenge (final) ===")
    logger.info(f"hard_success: {result.get('hard_success')}")
    logger.info(f"final_token: {result.get('final_token')}")
    logger.info(f"elapsed_ms: {result.get('local_elapsed_ms')}")


if __name__ == "__main__":
    main()
