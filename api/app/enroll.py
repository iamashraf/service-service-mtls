"""Fetch a cert and key from the mock CA."""
import time

import httpx


def fetch(ca_url: str, name: str, kind: str, dns: list[str]) -> dict:
    """POST /enroll and return {"cert_pem","key_pem","ca_pem"}.

    Retries connection errors only (20 x 250ms) while the CA starts; 4xx/5xx raise at once.
    """
    for attempt in range(20):
        try:
            r = httpx.post(f"{ca_url}/enroll", json={"name": name, "kind": kind, "dns": dns},
                           timeout=5)
            break
        except httpx.ConnectError:
            if attempt == 19:
                raise
            time.sleep(0.25)
    r.raise_for_status()
    return r.json()
