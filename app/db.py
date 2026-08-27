from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from app.config import get_settings


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_pw(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${digest}"


def check_pw(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    test = hashlib.sha256((salt + password).encode()).hexdigest()
    return hmac.compare_digest(test, digest)


@contextmanager
def connect():
    path = get_settings().db_path
    con = sqlite3.connect(path, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db() -> None:
    with connect() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                approve_token TEXT UNIQUE,
                binance_api_key TEXT NOT NULL DEFAULT '',
                binance_api_secret TEXT NOT NULL DEFAULT '',
                binance_uid TEXT NOT NULL DEFAULT '',
                binance_name TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                api_key TEXT UNIQUE NOT NULL,
                webhook_url TEXT NOT NULL DEFAULT '',
                webhook_secret TEXT NOT NULL DEFAULT '',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS invoices (
                invoice_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                bot_id INTEGER,
                telegram_id TEXT,
                amount TEXT NOT NULL,
                currency TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                txid TEXT,
                created_at TEXT NOT NULL,
                paid_at TEXT
            );
            CREATE TABLE IF NOT EXISTS used_tx (
                txid TEXT PRIMARY KEY,
                invoice_id TEXT NOT NULL,
                used_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS webhook_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id INTEGER,
                event TEXT,
                payload TEXT,
                status_code INTEGER,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                user_id INTEGER PRIMARY KEY,
                deposit_text TEXT NOT NULL DEFAULT '',
                success_text TEXT NOT NULL DEFAULT '',
                fail_not_found TEXT NOT NULL DEFAULT '',
                fail_mismatch TEXT NOT NULL DEFAULT ''
            );
            """
        )


DEFAULT_DEPOSIT = """🟡 Binance Pay Deposit

Pay ID: {pay_id}
Binance Name: {binance_name}

Amount: {amount} {currency}

✅ Send any exact amount to the Pay ID above
📝 Paste your Order ID below

⏰ Only payments started after opening this screen and completed within {minutes} minutes will be credited.

Please send your Order ID below:"""

DEFAULT_SUCCESS = """✅ Success — Done

Credited: {amount} {currency}
New balance: {balance} {currency}"""

DEFAULT_FAIL_NOT_FOUND = """❌ Disapproved (#{code}).

Order ID: {order_id}

We couldn't find that Order ID in our Binance Pay history. Make sure you copied the full ID from the receipt and that the payment completed within the 30-minute window.

This order did not match our records. If you believe this is a mistake, contact support."""

DEFAULT_FAIL_MISMATCH = """❌ Disapproved (#{code}).

Order ID: {order_id}

This order did not match our records. The paid amount is not the same as this invoice."""


def get_messages(user_id: int) -> dict:
    with connect() as con:
        row = con.execute("SELECT * FROM messages WHERE user_id=?", (user_id,)).fetchone()
    data = dict(row) if row else {}
    return {
        "deposit_text": data.get("deposit_text") or DEFAULT_DEPOSIT,
        "success_text": data.get("success_text") or DEFAULT_SUCCESS,
        "fail_not_found": data.get("fail_not_found") or DEFAULT_FAIL_NOT_FOUND,
        "fail_mismatch": data.get("fail_mismatch") or DEFAULT_FAIL_MISMATCH,
    }


def save_messages(user_id: int, deposit_text: str, success_text: str, fail_not_found: str, fail_mismatch: str) -> None:
    with connect() as con:
        con.execute(
            """INSERT INTO messages(user_id,deposit_text,success_text,fail_not_found,fail_mismatch)
               VALUES(?,?,?,?,?)
               ON CONFLICT(user_id) DO UPDATE SET
                 deposit_text=excluded.deposit_text,
                 success_text=excluded.success_text,
                 fail_not_found=excluded.fail_not_found,
                 fail_mismatch=excluded.fail_mismatch""",
            (user_id, deposit_text, success_text, fail_not_found, fail_mismatch),
        )


def create_user(email: str, password: str) -> dict[str, Any]:
    token = secrets.token_urlsafe(24)
    with connect() as con:
        cur = con.execute(
            "INSERT INTO users(email,password_hash,status,approve_token,created_at) VALUES(?,?,?,?,?)",
            (email.lower().strip(), hash_pw(password), "pending", token, utcnow()),
        )
        return {"id": cur.lastrowid, "email": email.lower().strip(), "approve_token": token}


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with connect() as con:
        return con.execute("SELECT * FROM users WHERE email=?", (email.lower().strip(),)).fetchone()


def get_user(user_id: int) -> Optional[sqlite3.Row]:
    with connect() as con:
        return con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def get_user_by_token(token: str) -> Optional[sqlite3.Row]:
    with connect() as con:
        return con.execute("SELECT * FROM users WHERE approve_token=?", (token,)).fetchone()


def set_status(user_id: int, status: str) -> None:
    with connect() as con:
        con.execute("UPDATE users SET status=? WHERE id=?", (status, user_id))


def list_users() -> list[sqlite3.Row]:
    with connect() as con:
        return con.execute("SELECT * FROM users ORDER BY id DESC").fetchall()


def pending_users() -> list[sqlite3.Row]:
    with connect() as con:
        return con.execute("SELECT * FROM users WHERE status='pending' ORDER BY id DESC").fetchall()


def save_binance(user_id: int, key: str, secret: str, uid: str, name: str) -> None:
    with connect() as con:
        con.execute(
            "UPDATE users SET binance_api_key=?, binance_api_secret=?, binance_uid=?, binance_name=? WHERE id=?",
            (key.strip(), secret.strip(), uid.strip(), name.strip(), user_id),
        )


def create_bot(user_id: int, name: str, webhook_url: str = "") -> dict[str, Any]:
    api_key = "pk_live_" + secrets.token_hex(16)
    secret = "whsec_" + secrets.token_hex(16)
    with connect() as con:
        cur = con.execute(
            "INSERT INTO bots(user_id,name,api_key,webhook_url,webhook_secret,created_at) VALUES(?,?,?,?,?,?)",
            (user_id, name, api_key, webhook_url, secret, utcnow()),
        )
        return {
            "id": cur.lastrowid,
            "api_key": api_key,
            "webhook_secret": secret,
            "webhook_url": webhook_url,
            "name": name,
        }


def list_bots(user_id: int) -> list[sqlite3.Row]:
    with connect() as con:
        return con.execute("SELECT * FROM bots WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()


def get_bot(bot_id: int) -> Optional[sqlite3.Row]:
    with connect() as con:
        return con.execute("SELECT * FROM bots WHERE id=?", (bot_id,)).fetchone()


def get_bot_by_key(api_key: str) -> Optional[sqlite3.Row]:
    with connect() as con:
        return con.execute("SELECT * FROM bots WHERE api_key=? AND active=1", (api_key,)).fetchone()


def update_bot_webhook(bot_id: int, user_id: int, webhook_url: str) -> None:
    with connect() as con:
        con.execute(
            "UPDATE bots SET webhook_url=? WHERE id=? AND user_id=?",
            (webhook_url.strip(), bot_id, user_id),
        )


def create_invoice(invoice_id: str, user_id: int, bot_id: int, telegram_id: str, amount: str, currency: str) -> None:
    with connect() as con:
        con.execute(
            "INSERT INTO invoices(invoice_id,user_id,bot_id,telegram_id,amount,currency,status,created_at) VALUES(?,?,?,?,?,?,'PENDING',?)",
            (invoice_id, user_id, bot_id, telegram_id, amount, currency, utcnow()),
        )


def get_invoice(invoice_id: str) -> Optional[sqlite3.Row]:
    with connect() as con:
        return con.execute("SELECT * FROM invoices WHERE invoice_id=?", (invoice_id,)).fetchone()


def mark_paid(invoice_id: str, txid: str) -> None:
    with connect() as con:
        con.execute(
            "UPDATE invoices SET status='PAID', txid=?, paid_at=? WHERE invoice_id=? AND status!='PAID'",
            (txid, utcnow(), invoice_id),
        )
        con.execute(
            "INSERT OR IGNORE INTO used_tx(txid,invoice_id,used_at) VALUES(?,?,?)",
            (txid, invoice_id, utcnow()),
        )


def tx_used(txid: str) -> bool:
    with connect() as con:
        return con.execute("SELECT 1 FROM used_tx WHERE txid=?", (txid,)).fetchone() is not None


def list_invoices(user_id: int, limit: int = 50) -> list[sqlite3.Row]:
    with connect() as con:
        return con.execute(
            "SELECT * FROM invoices WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()


def log_webhook(bot_id: int, event: str, payload: str, status_code: int) -> None:
    with connect() as con:
        con.execute(
            "INSERT INTO webhook_logs(bot_id,event,payload,status_code,created_at) VALUES(?,?,?,?,?)",
            (bot_id, event, payload, status_code, utcnow()),
        )
