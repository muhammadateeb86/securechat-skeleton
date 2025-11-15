# storage/db.py
"""PyMySQL-based user store (username login)."""
import os
from dotenv import load_dotenv
load_dotenv()
import pymysql
from pymysql.cursors import DictCursor
from hashlib import sha256
import secrets

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_USER = os.getenv("DB_USER", "securechat_user")
DB_PASS = os.getenv("DB_PASS", "changeme")
DB_NAME = os.getenv("DB_NAME", "securechat")

DSN = dict(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME, cursorclass=DictCursor, autocommit=True)

SCHEMA_STMT = """
CREATE DATABASE IF NOT EXISTS securechat;
USE securechat;
CREATE TABLE IF NOT EXISTS users (
  username VARCHAR(60) PRIMARY KEY,
  email VARCHAR(120),
  salt BINARY(16),
  pwd_hash CHAR(64)
);
"""

def get_conn():
    return pymysql.connect(**DSN)

def init_db():
    # connect without database to create it
    tmp = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, cursorclass=DictCursor, autocommit=True)
    cur = tmp.cursor()
    for stmt in SCHEMA_STMT.split(";"):
        s = stmt.strip()
        if s:
            cur.execute(s)
    cur.close()
    tmp.close()

def register_user(username: str, email: str, password: str) -> (bool, str):
    conn = get_conn()
    cur = conn.cursor()
    # check exists
    cur.execute("SELECT username FROM users WHERE username=%s", (username,))
    if cur.fetchone():
        cur.close(); conn.close()
        return False, "exists"
    salt = secrets.token_bytes(16)
    pwd_hash = sha256(salt + password.encode()).hexdigest()
    cur.execute("INSERT INTO users(username,email,salt,pwd_hash) VALUES (%s,%s,%s,%s)", (username, email, salt, pwd_hash))
    cur.close(); conn.close()
    return True, "ok"

def verify_login(username: str, password: str) -> (bool, str):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT salt, pwd_hash FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        return False, "no_user"
    salt = row["salt"]
    expected = row["pwd_hash"]
    got = sha256(salt + password.encode()).hexdigest()
    # constant-time compare recommended; use simple compare for assignment but note in report
    if got == expected:
        return True, "ok"
    return False, "bad_pwd"
