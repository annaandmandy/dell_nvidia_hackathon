#!/usr/bin/env python3
"""Verify a canonical JSON payload signed with Ed25519."""

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


def canonical_bytes(path: Path) -> bytes:
    data = json.loads(path.read_text(encoding="utf-8"))
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("payload", type=Path)
    parser.add_argument("signature", type=Path)
    parser.add_argument("public_key", type=Path)
    args = parser.parse_args()

    key = serialization.load_pem_public_key(args.public_key.read_bytes())
    signature = base64.b64decode(args.signature.read_text(encoding="ascii").strip())
    try:
        key.verify(signature, canonical_bytes(args.payload))
    except InvalidSignature:
        print("INVALID: payload does not match the signature")
        return 1
    print("VALID: registered issuer key signed this exact canonical JSON payload")
    return 0


if __name__ == "__main__":
    sys.exit(main())
