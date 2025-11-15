# common/protocol.py
from pydantic import BaseModel

class HelloModel(BaseModel):
    type: str
    client_cert: str = None  # base64 PEM or PEM string
    nonce: str

class ServerHelloModel(BaseModel):
    type: str
    server_cert: str
    nonce: str

class DHClientModel(BaseModel):
    type: str
    p: int
    g: int
    A: int

class DHServerModel(BaseModel):
    type: str
    B: int

class EncPayloadModel(BaseModel):
    ct: str  # base64 ciphertext

class RegisterModel(BaseModel):
    email: str
    username: str
    pwd: str  # plaintext in this structure but transmitted encrypted under AES

class LoginModel(BaseModel):
    username: str
    pwd: str

class ChatMsgModel(BaseModel):
    type: str
    seqno: int
    ts: int
    ct: str
    sig: str

class ReceiptModel(BaseModel):
    type: str
    peer: str
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig: str
