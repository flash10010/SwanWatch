#!/usr/bin/env python3
import base64, secrets, urllib.parse
secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
label=urllib.parse.quote('SwanWatch:admin')
issuer=urllib.parse.quote('SwanWatch')
print(f'TOTP_SECRET={secret}')
print(f'otpauth://totp/{label}?secret={secret}&issuer={issuer}')
