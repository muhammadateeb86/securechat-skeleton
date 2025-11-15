# app/server.py
"""Console TCP server (no TLS). Runs on port 9000 and implements the protocol."""
import socket, threading, json, os, time
from pathlib import Path
from common.utils import b64, ub64, now_ms, sha256_hex, json_dumps
from common.protocol import HelloModel, ServerHelloModel, DHClientModel, DHServerModel, EncPayloadModel, ChatMsgModel, ReceiptModel
from crypto.pki import verify_cert_against_ca, cert_fingerprint_sha256
from crypto.dh import GROUP14_P, GROUP14_G, gen_private, gen_public, compute_shared, kdf_trunc16_from_int
from crypto.aes import aes_ecb_decrypt, aes_ecb_encrypt
from crypto.sign import rsa_verify_pem, rsa_sign_pem
from storage.db import verify_login, register_user, init_db
from storage.transcript import append_line, compute_transcript_hash, write_receipt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from rich import print

# configuration
HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "9000"))
CERT_DIR = Path("certs")
CA_CRT = (CERT_DIR / "ca.crt").read_bytes()
SERVER_KEY = (CERT_DIR / "server.key").read_bytes()
SERVER_CRT = (CERT_DIR / "server.crt").read_bytes()

init_db()

def handle_client(conn, addr):
    print(f"[yellow]client connected {addr}[/]")
    session_id = f"{addr[0].replace('.','_')}_{int(time.time())}"
    seq_expected = 1
    # 1. receive hello
    data = conn.recv(65536)
    try:
        hello = json.loads(data.decode())
    except Exception:
        conn.close(); return
    # client cert is expected in PEM string
    client_cert_pem = hello.get("client cert", None)
    if not client_cert_pem:
        conn.send(b"BAD_CERT"); conn.close(); return
    ok, reason = verify_cert_against_ca(client_cert_pem.encode(), CA_CRT)
    if not ok:
        print(f"[red]BAD CERT: {reason}[/]")
        conn.send(b"BAD_CERT"); conn.close(); return
    # send server hello
    srv_nonce = os.urandom(16)
    srv_hello = {"type":"server hello", "server cert": SERVER_CRT.decode(), "nonce": b64(srv_nonce)}
    conn.send(json_dumps(srv_hello).encode())
    # 2. expect DH client (temp)
    data = conn.recv(131072)
    dhc = json.loads(data.decode())
    p = int(dhc["p"]); g = int(dhc["g"]); A = int(dhc["A"])
    b = gen_private()
    B = gen_public(g, b, p)
    conn.send(json_dumps({"type":"dh server","B": B}).encode())
    Ks = compute_shared(A, b, p)
    Ktemp = kdf_trunc16_from_int(Ks)
    # 3. expect encrypted payload (register or login)
    data = conn.recv(131072)
    enc = json.loads(data.decode())
    ct = ub64(enc["ct"])
    try:
        pt = aes_ecb_decrypt(Ktemp, ct)
        payload = json.loads(pt.decode())
    except Exception:
        conn.send(b"BAD_ENC"); conn.close(); return
    if payload.get("type") == "register":
        username = payload.get("username"); email = payload.get("email"); pwd = payload.get("pwd")
        ok, msg = register_user(username, email, pwd)
        if not ok:
            conn.send(json_dumps({"status":"error","reason":msg}).encode()); conn.close(); return
        conn.send(json_dumps({"status":"ok","msg":"registered"}).encode())
    elif payload.get("type") == "login":
        username = payload.get("username"); pwd = payload.get("pwd")
        ok, msg = verify_login(username, pwd)
        if not ok:
            conn.send(json_dumps({"status":"error","reason":msg}).encode()); conn.close(); return
        conn.send(json_dumps({"status":"ok","msg":"logged_in"}).encode())
    else:
        conn.send(b"BAD_REQ"); conn.close(); return

    # 4. Post-auth DH for session key
    data = conn.recv(131072)
    dhc2 = json.loads(data.decode())
    A2 = int(dhc2["A"])
    b2 = gen_private()
    B2 = gen_public(GROUP14_G, b2, GROUP14_P)
    conn.send(json_dumps({"type":"dh server", "B": B2}).encode())
    Ks2 = compute_shared(A2, b2, GROUP14_P)
    Ksession = kdf_trunc16_from_int(Ks2)

    # 5. message loop
    first_seq = None
    last_seq = None
    client_cert_bytes = client_cert_pem.encode()
    client_cert = x509.load_pem_x509_certificate(client_cert_bytes)
    client_pub_pem = client_cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    while True:
        try:
            raw = conn.recv(262144)
            if not raw:
                break
            m = json.loads(raw.decode())
        except Exception:
            break
        if m.get("type") == "msg":
            seq = int(m["seqno"]); ts = int(m["ts"])
            ct_b64 = m["ct"]; sig_b64 = m["sig"]
            ct = ub64(ct_b64); sig = ub64(sig_b64)
            # replay check
            if seq != seq_expected:
                conn.send(json_dumps({"status":"error","reason":"REPLAY_OR_ORDER"}).encode()); continue
            # recompute hash
            from hashlib import sha256
            h = sha256(str(seq).encode() + str(ts).encode() + ct).digest()
            if not rsa_verify_pem(client_pub_pem, h, sig):
                conn.send(json_dumps({"status":"error","reason":"SIG_FAIL"}).encode()); continue
            # decrypt ct and print
            try:
                pt = aes_ecb_decrypt(Ksession, ct)
            except Exception:
                conn.send(json_dumps({"status":"error","reason":"DECRYPT_FAIL"}).encode()); continue
            text = pt.decode(errors="replace")
            print(f"[green][{seq}] {text}[/]")
            # append transcript line
            fp = cert_fingerprint_sha256(client_cert_bytes)
            line = f"{seq}|{ts}|{ct_b64}|{sig_b64}|{fp}"
            append_line(session_id, line)
            if first_seq is None: first_seq = seq
            last_seq = seq
            seq_expected += 1
            conn.send(json_dumps({"status":"ok"}).encode())
        elif m.get("type") == "receipt":
            # accept client receipt optionally
            conn.send(json_dumps({"status":"ok","msg":"receipt_received"}).encode())
        elif m.get("type") == "exit":
            conn.send(json_dumps({"status":"ok","msg":"bye"}).encode())
            break
        else:
            conn.send(json_dumps({"status":"error","reason":"UNKNOWN_TYPE"}).encode())
    # on session close produce server receipt
    th = compute_transcript_hash(session_id)
    sig = rsa_sign_pem(SERVER_KEY, th.encode())
    receipt = {"type":"receipt","peer":"server","first_seq": first_seq or 0, "last_seq": last_seq or 0, "transcript_sha256": th, "sig": sig.hex()}
    Path(f"transcripts/receipt_server_{session_id}.json").write_text(json_dumps(receipt))
    print(f"[blue]session {session_id} closed, receipt written[/]")
    conn.close()

def run():
    Path("transcripts").mkdir(exist_ok=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[bold cyan]SecureChat server listening on {HOST}:{PORT}[/]")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

if __name__ == "__main__":
    run()
