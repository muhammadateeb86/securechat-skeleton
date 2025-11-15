# app/client.py
"""Console client that supports register/login and continuous chat until /exit."""
import socket, json, os, time
from pathlib import Path
from common.utils import b64, ub64, now_ms, json_dumps
from common.protocol import DHClientModel
from crypto.dh import GROUP14_P, GROUP14_G, gen_private, gen_public, compute_shared, kdf_trunc16_from_int
from crypto.aes import aes_ecb_encrypt, aes_ecb_decrypt
from crypto.sign import rsa_sign_pem, rsa_verify_pem
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from rich.console import Console
from rich.prompt import Prompt
from getpass import getpass
console = Console()

CERT_DIR = Path("certs")
CLIENT_KEY = (CERT_DIR / "client.key").read_bytes()
CLIENT_CRT = (CERT_DIR / "client.crt").read_bytes()
CA_CRT = (CERT_DIR / "ca.crt").read_bytes()

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "9000"))

def verify_server_cert(server_cert_pem: bytes) -> bool:
    # local basic checks: issuer should be CA subject and signature verifies
    from crypto.pki import verify_cert_against_ca
    ok, reason = verify_cert_against_ca(server_cert_pem, CA_CRT)
    if not ok:
        console.print(f"[red]Server cert verification failed: {reason}[/]")
    return ok

def run():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    console.print("[bold green]Connected to server[/]")
    hello = {"type":"hello", "client cert": CLIENT_CRT.decode(), "nonce": b64(os.urandom(16))}
    s.send(json_dumps(hello).encode())
    data = s.recv(131072)
    srv = json.loads(data.decode())
    server_cert_pem = srv.get("server_cert", srv.get("server cert", None)) or srv.get("server cert")
    if not server_cert_pem:
        console.print("[red]No server cert received[/]"); s.close(); return
    if not verify_server_cert(server_cert_pem.encode()):
        s.close(); return

    # Temporary DH for registration/login
    a = gen_private()
    A = gen_public(GROUP14_G, a, GROUP14_P)
    s.send(json_dumps({"type":"dh client","p": GROUP14_P, "g": GROUP14_G, "A": A}).encode())
    data = s.recv(131072)
    d = json.loads(data.decode()); B = int(d["B"])
    Ks = compute_shared(B, a, GROUP14_P)
    Ktemp = kdf_trunc16_from_int(Ks)

    # Ask user: register or login
    mode = Prompt.ask("Do you want to [r]egister or [l]ogin?", choices=["r","l"])
    if mode == "r":
        email = Prompt.ask("Email")
        username = Prompt.ask("Username")
        pwd = getpass("Password: ")
        payload = {"type":"register", "email": email, "username": username, "pwd": pwd}
    else:
        username = Prompt.ask("Username")
        pwd = getpass("Password: ")
        payload = {"type":"login", "username": username, "pwd": pwd}
    ct = aes_ecb_encrypt(Ktemp, json_dumps(payload).encode())
    s.send(json_dumps({"ct": b64(ct)}).encode())
    resp = json.loads(s.recv(131072).decode())
    if resp.get("status") != "ok":
        console.print(f"[red]Server error: {resp}[/]"); s.close(); return
    console.print("[green]Auth success[/]")

    # Session DH
    a2 = gen_private(); A2 = gen_public(GROUP14_G, a2, GROUP14_P)
    s.send(json_dumps({"type":"dh client","A": A2}).encode())
    d = json.loads(s.recv(131072).decode()); B2 = int(d["B"])
    Ks2 = compute_shared(B2, a2, GROUP14_P)
    Ksession = kdf_trunc16_from_int(Ks2)

    # Chat loop
    seq = 1
    client_priv_pem = CLIENT_KEY
    while True:
        text = Prompt.ask("[bold blue]You[/]")
        if text.strip() == "/exit":
            s.send(json_dumps({"type":"exit"}).encode()); break
        ts = now_ms()
        ct = aes_ecb_encrypt(Ksession, text.encode())
        # compute h = SHA256(seq||ts||ct)
        from hashlib import sha256
        h = sha256(str(seq).encode() + str(ts).encode() + ct).digest()
        sig = rsa_sign_pem(client_priv_pem, h)
        msg = {"type":"msg","seqno": seq, "ts": ts, "ct": b64(ct), "sig": b64(sig)}
        s.send(json_dumps(msg).encode())
        ack = json.loads(s.recv(131072).decode())
        if ack.get("status") != "ok":
            console.print(f"[red]Server returned error: {ack}[/]")
        else:
            console.print(f"[green]sent ({seq})[/]")
            seq += 1
    s.close()
    console.print("[cyan]Disconnected[/]")

if __name__ == "__main__":
    run()
