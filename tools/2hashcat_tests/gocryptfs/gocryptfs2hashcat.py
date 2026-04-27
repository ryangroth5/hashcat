#!/usr/bin/env python3

import json
import base64
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "gocryptfs.conf"

with open(path) as f:
    c = json.load(f)

if "HKDF" not in c.get("FeatureFlags", []):
    print("Error: HKDF feature flag not present. Only gocryptfs >= v1.3 is supported.", file=sys.stderr)
    sys.exit(1)

s    = c["ScryptObject"]
salt = base64.b64encode(base64.b64decode(s["Salt"])).decode().rstrip("=")
ek   = base64.b64encode(base64.b64decode(c["EncryptedKey"])).decode().rstrip("=")

print(f"$gocryptfs${s['N']}${s['R']}${s['P']}${salt}${ek}")
