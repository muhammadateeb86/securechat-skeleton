# storage/transcript.py
from pathlib import Path
from hashlib import sha256
from crypto.sign import rsa_sign_pem
import json
from common.utils import now_ms
TRANS_DIR = Path("transcripts")
TRANS_DIR.mkdir(exist_ok=True)

def append_line(session_id: str, line: str):
    p = TRANS_DIR / f"{session_id}.log"
    with open(p, "ab") as f:
        f.write(line.encode() + b"\n")

def compute_transcript_hash(session_id: str) -> str:
    p = TRANS_DIR / f"{session_id}.log"
    data = p.read_bytes() if p.exists() else b""
    return sha256(data).hexdigest()

def write_receipt(session_id: str, signer_private_pem: bytes, first_seq: int, last_seq: int):
    th = compute_transcript_hash(session_id)
    sig = rsa_sign_pem(signer_private_pem, th.encode())
    rec = {
        "type":"receipt",
        "peer":"server",
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": th,
        "sig": sig.hex()
    }
    Path = TRANS_DIR / f"{session_id}_receipt.json"
    with open(Path, "w") as f:
        json.dump(rec, f, indent=2)
    return rec
