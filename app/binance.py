from __future__ import annotations
import hashlib, hmac, time
from urllib.parse import urlencode
import httpx
BASE = "https://api.binance.com"
class BinanceError(Exception):
    pass
def _offset():
    try:
        r = httpx.get(f"{BASE}/api/v3/time", timeout=10)
        return int(r.json()["serverTime"]) - int(time.time()*1000)
    except Exception:
        return 0
def signed_get(path, params, key, secret):
    if not key or not secret:
        raise BinanceError("Binance API key and secret are not set.")
    params = dict(params or {})
    params["timestamp"] = int(time.time()*1000) + _offset()
    params["recvWindow"] = 60000
    q = urlencode(params)
    sig = hmac.new(secret.encode(), q.encode(), hashlib.sha256).hexdigest()
    url = f"{BASE}{path}?{q}&signature={sig}"
    last = None
    for _ in range(3):
        try:
            r = httpx.get(url, headers={"X-MBX-APIKEY": key}, timeout=45)
            data = r.json()
            if r.status_code != 200:
                raise BinanceError(str(data.get("msg") if isinstance(data, dict) else data))
            return data
        except BinanceError:
            raise
        except Exception as exc:
            last = exc
            time.sleep(1)
    raise BinanceError(f"Binance network error: {last}")
def live_balances(key=None, secret=None, coin_filter=""):
    if not key or not secret:
        return {"ok": True, "usdt": 0.0, "items": []}
    spot = signed_get("/api/v3/account", {}, key, secret)
    items = []
    for b in spot.get("balances") or []:
        free = float(b.get("free") or 0); locked = float(b.get("locked") or 0)
        if free+locked <= 0: continue
        asset = str(b.get("asset") or "")
        if coin_filter and asset.upper() != coin_filter.upper(): continue
        items.append({"asset": asset, "free": free, "locked": locked, "total": free+locked, "wallet": "SPOT"})
    usdt = sum(i["total"] for i in items if i["asset"]=="USDT")
    return {"ok": True, "usdt": usdt, "items": items}
def _ids(row):
    out = []
    if not isinstance(row, dict): return out
    for k in ("orderId","transactionId","txnId","txId","note","id"):
        v = row.get(k)
        if v is not None: out.append(str(v).strip())
    return out
def verify_any(txid, expected_amount, coin, key, secret):
    needle = str(txid or "").strip()
    if len(needle) < 8:
        raise BinanceError("Order ID too short.")
    pay = signed_get("/sapi/v1/pay/transactions", {"limit": 100}, key, secret)
    rows = pay.get("data") if isinstance(pay, dict) else pay
    if isinstance(rows, list):
        for row in rows:
            if needle not in _ids(row): continue
            amount = float(row.get("amount") or 0)
            currency = str(row.get("currency") or coin).upper()
            if amount <= 0: raise BinanceError("Outgoing transfer.")
            if abs(amount - float(expected_amount)) > 0.01:
                raise BinanceError(f"Amount mismatch: invoice {expected_amount}, paid {amount}")
            return {"transactionId": str(row.get("transactionId") or needle), "amount": amount, "coin": currency, "network": "BINANCE_PAY"}
    raise BinanceError("Exact Order ID not found.")
