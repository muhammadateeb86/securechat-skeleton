# common/utils.py
import base64, time, json
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s)

def now_ms() -> int:
    return int(time.time() * 1000)

def sha256_hex(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()

def json_dumps(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
