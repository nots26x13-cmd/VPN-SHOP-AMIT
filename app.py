"""
VPN SHOP - Bot + Website, ONE Render service
------------------------------------------------------
This single Flask app serves everything:
  - /             -> the Mini App store (public/vpn.html)
  - /api/...      -> JSON API the Mini App calls (see SECURITY MODEL below)
  - /success.html -> payment gateway redirect page
  - /cancel.html  -> payment gateway redirect page
  - /webhook/<TOKEN> -> Telegram sends bot updates here
  - /health       -> tiny route the self-ping loop hits to stay awake

Folder layout expected next to this file:
    app.py
    requirements.txt
    Procfile
    public/
        vpn.html
        success.html
        cancel.html

============================================================
SECURITY MODEL (read this before deploying)
============================================================
Earlier versions of this project had the Mini App (vpn.html) talk straight
to Firebase from the browser using the Firebase client SDK. That meant the
ONLY thing stopping a user from opening devtools and calling
`update(ref(db,'orders/x'), {st:'Approved', email:'...', pass:'...'})`
themselves - skipping payment entirely - was whatever Firebase Realtime
Database security rules happened to be set. The "admin" check in that old
code was purely cosmetic (it just hid/showed a button); it did not gate
any database write.

This version closes that hole by moving every write, and every read of
sensitive data (stock credentials, other users' orders), onto this server:
  - The Mini App no longer imports the Firebase SDK or holds a database
    reference at all. It only talks to the /api/... routes below over
    HTTPS, the same origin the page was served from.
  - Every /api/... route that changes anything, or that returns anything
    user-specific, requires the header `X-Telegram-Init-Data`, which is
    Telegram's own `tg.initData` string - a payload Telegram itself signs
    with your BOT_TOKEN. `verify_init_data()` below re-checks that
    signature server-side, so the user id it trusts is the one Telegram
    signed, never a value the client claims in a JSON body. Client-sent
    "uid" fields are ignored everywhere.
  - Order price is always looked up from the vpns/ node server-side by
    plan key ("p1" or "p2") - the client can never submit its own price.
  - Admin-only routes additionally check that verified uid is in
    ADMIN_IDS, server-side. There is no client-side admin bypass anymore.
  - This server authenticates to Firebase with a service account (see
    FIREBASE_SERVICE_ACCOUNT_JSON below) instead of relying on public
    database rules. Once that's set up, set your Firebase Realtime
    Database rules to:
        { "rules": { ".read": false, ".write": false } }
    A locked-down ruleset like that means even someone who has your
    databaseURL and apiKey (neither of which is secret - Firebase's own
    docs say apiKey isn't a security boundary) gets nothing without going
    through this server's auth checks.

DEPLOY ON RENDER:
  1. Push this whole folder (app.py, requirements.txt, Procfile, public/)
     to a GitHub repo
  2. On Render: New -> Web Service -> connect the repo
  3. Environment: Python 3
  4. Build Command:  pip install -r requirements.txt
  5. Start Command:  gunicorn app:app  (Procfile already sets this)
  6. Add Environment Variables (Render dashboard -> Environment):
        BOT_TOKEN                    <- get a FRESH one from @BotFather.
                                         The token that used to be hardcoded
                                         in this file's source was exposed
                                         to anyone who had this zip - treat
                                         it as compromised and revoke it
                                         with /revoke in @BotFather.
        NS_API_KEY, NS_SECRET_KEY, NS_BRAND_KEY   <- from your payment gateway
        FIREBASE_SERVICE_ACCOUNT_JSON             <- see below
     (Don't hardcode secrets in code that goes on GitHub - use env vars.)
     You do NOT need to set WEBAPP_URL / SUCCESS_REDIRECT_URL /
     CANCEL_REDIRECT_URL - they're built automatically from Render's own
     URL since this app serves those pages itself.
  7. Deploy. The app auto-registers itself as the Telegram webhook on
     startup using Render's URL - no manual step needed.

GETTING FIREBASE_SERVICE_ACCOUNT_JSON:
  Firebase Console -> your project -> gear icon -> Project settings ->
  Service accounts tab -> "Generate new private key". This downloads a
  .json file. Open it, copy the ENTIRE contents, and paste that whole
  JSON blob in as the value of one env var, FIREBASE_SERVICE_ACCOUNT_JSON,
  on Render. Then lock down your Realtime Database rules as shown above -
  this service account authenticates with a Google OAuth2 token that
  bypasses those rules for this server only, so the app keeps working
  while every other reader/writer gets locked out.

KEEP IT AWAKE 24/7:
  A background thread pings this app's own "/health" route every 5
  minutes so Render always sees recent traffic and (usually) won't spin
  the free instance down. For an absolute guarantee, upgrade to Render's
  paid "Starter" instance instead.

IMPORTANT - Procfile uses --workers 1:
  The Broadcast feature uses telebot's "next step handler", which is only
  kept in that one process's memory. Running more than 1 gunicorn worker
  would randomly break it (the admin's next message might land on a
  different worker that doesn't know it's expecting a broadcast). Keep
  workers at 1 - --threads 4 already lets it handle several requests
  concurrently without needing more processes.
"""

import os
import json
import time
import hmac
import hashlib
import threading
import traceback
from datetime import datetime
from functools import wraps
from urllib.parse import parse_qsl
from zoneinfo import ZoneInfo

import requests
import telebot
from telebot import types
from flask import Flask, request, send_from_directory, jsonify
from google.oauth2 import service_account
import google.auth.transport.requests as ga_requests

# ================= CONFIG (env vars override these defaults) =================
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
if not BOT_TOKEN:
    raise RuntimeError(
        "BOT_TOKEN environment variable is required. Get a FRESH token from "
        "@BotFather - do not reuse any token that was ever hardcoded in "
        "source code, since that copy must be treated as leaked."
    )
BOT_USERNAME = os.environ.get("BOT_USERNAME", "vpnshop02_bot")

NS_API_KEY = os.environ.get("NS_API_KEY", "")
NS_SECRET_KEY = os.environ.get("NS_SECRET_KEY", "")
NS_BRAND_KEY = os.environ.get("NS_BRAND_KEY", "")

NS_CREATE_URL = "https://pay.nstopup.com/api/payment/create"
NS_VERIFY_URL = "https://pay.nstopup.com/api/payment/verify"

FIREBASE_DB = os.environ.get("FIREBASE_DB", "https://vpn-store-s26x-default-rtdb.firebaseio.com")

# Render sets this automatically for every deploy - no need to set it yourself
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL")


def _default_url(env_name, path):
    """Use an explicit env var if set, otherwise build the URL from this
    same Render service (since we now serve the HTML files ourselves)."""
    v = os.environ.get(env_name)
    if v:
        return v
    if RENDER_EXTERNAL_URL:
        return RENDER_EXTERNAL_URL.rstrip("/") + path
    return "http://localhost:5000" + path  # local dev fallback


WEBAPP_URL = _default_url("WEBAPP_URL", "/vpn.html")
SUCCESS_REDIRECT_URL = _default_url("SUCCESS_REDIRECT_URL", "/success.html")
CANCEL_REDIRECT_URL = _default_url("CANCEL_REDIRECT_URL", "/cancel.html")

ADMIN_IDS = [8505710811, 7940769450]
BD_TZ = ZoneInfo("Asia/Dhaka")

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML", threaded=True)
app = Flask(__name__, static_folder="public", static_url_path="")

# Reuse TCP/TLS connections instead of opening a new one per request -> faster
fb_session = requests.Session()
ns_session = requests.Session()
NS_HEADERS = {
    "API-KEY": NS_API_KEY,
    "Content-Type": "application/json",
    "SECRET-KEY": NS_SECRET_KEY,
    "BRAND-KEY": NS_BRAND_KEY,
}

# ================= FIREBASE AUTH (service account) =================
# The server authenticates every Firebase REST call with a Google OAuth2
# token minted from a service account, instead of relying on open database
# rules. This lets you lock the database rules down to ".read": false,
# ".write": false for everyone except this server. See the module
# docstring above for how to generate FIREBASE_SERVICE_ACCOUNT_JSON.
FIREBASE_SA_JSON = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "")
_fb_creds = None
if FIREBASE_SA_JSON:
    try:
        _fb_creds = service_account.Credentials.from_service_account_info(
            json.loads(FIREBASE_SA_JSON),
            scopes=[
                "https://www.googleapis.com/auth/firebase.database",
                "https://www.googleapis.com/auth/userinfo.email",
            ],
        )
    except Exception:
        traceback.print_exc()
        print("FIREBASE_SERVICE_ACCOUNT_JSON is set but could not be parsed - Firebase calls will fail.")
else:
    print("WARNING: FIREBASE_SERVICE_ACCOUNT_JSON is not set. Firebase calls will fail "
          "once your database rules are locked down (and they should be - see docstring).")


def _fb_auth_headers():
    if not _fb_creds:
        return {}
    if not _fb_creds.valid:
        _fb_creds.refresh(ga_requests.Request())
    return {"Authorization": f"Bearer {_fb_creds.token}"}


# ================= FIREBASE HELPERS =================
def db_get(path):
    r = fb_session.get(f"{FIREBASE_DB}/{path}.json", headers=_fb_auth_headers(), timeout=10)
    r.raise_for_status()
    return r.json()


def db_patch(path, data):
    """Shallow-merge `data` into whatever already lives at `path`."""
    r = fb_session.patch(f"{FIREBASE_DB}/{path}.json", headers=_fb_auth_headers(), json=data, timeout=10)
    r.raise_for_status()
    return r.json()


def db_put(path, data):
    """Overwrite the value at `path` entirely."""
    r = fb_session.put(f"{FIREBASE_DB}/{path}.json", headers=_fb_auth_headers(), json=data, timeout=10)
    r.raise_for_status()
    return r.json()


def db_push(path, data):
    """Create a new child under `path` with a Firebase-generated key.
    Returns the raw REST response, e.g. {"name": "-NxxxxxxxxxxxxxxXX"}."""
    r = fb_session.post(f"{FIREBASE_DB}/{path}.json", headers=_fb_auth_headers(), json=data, timeout=10)
    r.raise_for_status()
    return r.json()


def db_delete(path):
    fb_session.delete(f"{FIREBASE_DB}/{path}.json", headers=_fb_auth_headers(), timeout=10)


# ================= TELEGRAM MINI APP AUTH =================
def verify_init_data(init_data, max_age_seconds=86400):
    """Cryptographically verify a Telegram Mini App `initData` string per
    Telegram's official algorithm. Returns the parsed dict (with 'user'
    decoded into a dict) if the signature is valid and fresh, else None.

    This is the ONLY trustworthy source of "which Telegram user is this" -
    a uid the client sends in a JSON body is never trusted for anything
    that grants access, money, or data."""
    if not init_data:
        return None
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    except Exception:
        return None

    recv_hash = pairs.pop("hash", None)
    if not recv_hash:
        return None

    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(computed_hash, recv_hash):
        return None

    try:
        auth_date = int(pairs.get("auth_date", "0"))
    except ValueError:
        return None
    if time.time() - auth_date > max_age_seconds:
        return None

    if "user" in pairs:
        try:
            pairs["user"] = json.loads(pairs["user"])
        except Exception:
            pairs["user"] = None

    return pairs


def get_auth(req):
    """Returns (uid:int, is_admin:bool, user:dict) or (None, False, None)."""
    data = verify_init_data(req.headers.get("X-Telegram-Init-Data", ""))
    if not data or not data.get("user"):
        return None, False, None
    user = data["user"]
    uid = user.get("id")
    if uid is None:
        return None, False, None
    return int(uid), int(uid) in ADMIN_IDS, user


def require_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        uid, is_admin, user = get_auth(request)
        if uid is None:
            return jsonify({"error": "unauthorized"}), 401
        return f(uid, is_admin, user, *a, **kw)
    return wrapper


def require_admin(f):
    @wraps(f)
    def wrapper(*a, **kw):
        uid, is_admin, user = get_auth(request)
        if uid is None:
            return jsonify({"error": "unauthorized"}), 401
        if not is_admin:
            return jsonify({"error": "forbidden"}), 403
        return f(uid, user, *a, **kw)
    return wrapper


# ================= TIME HELPER (Bangladesh) =================
def bd_now_str():
    now = datetime.now(BD_TZ)
    time_part = now.strftime("%I:%M %p")
    if time_part.startswith("0"):
        time_part = time_part[1:]
    return f"{time_part} - {now.month}/{now.day}/{now.year}"


# ================= USER TRACKING =================
def save_user_once(message):
    """Saves the user to Firebase the first time they're seen. Returns True
    if this was a new save, False if the user already existed (so we never
    overwrite/duplicate on repeat /start)."""
    uid = str(message.from_user.id)
    existing = db_get(f"bot_users/{uid}")
    if existing:
        return False
    db_patch(f"bot_users/{uid}", {
        "name": message.from_user.first_name or "",
        "username": message.from_user.username or "",
        "joined": bd_now_str(),
    })
    return True


def user_menu():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(types.KeyboardButton("🛒 Open VPN Shop", web_app=types.WebAppInfo(WEBAPP_URL)))
    return markup


def admin_menu():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(types.KeyboardButton("🛒 Open VPN Shop", web_app=types.WebAppInfo(WEBAPP_URL)))
    markup.add(types.KeyboardButton("📊 TOTAL USER"), types.KeyboardButton("📢 BROADCAST"))
    return markup


# ================= START HANDLER =================
@bot.message_handler(commands=["start"])
def handle_start(message):
    save_user_once(message)
    parts = message.text.split(maxsplit=1)
    payload = parts[1] if len(parts) > 1 else ""

    try:
        if payload.startswith("pay_"):
            start_payment(message, payload[len("pay_"):])
        elif payload.startswith("verify_"):
            handle_payment_success(message, payload[len("verify_"):])
        elif payload.startswith("cancel"):
            markup = admin_menu() if message.from_user.id in ADMIN_IDS else user_menu()
            bot.send_message(
                message.chat.id,
                "⚠️ পেমেন্ট বাতিল করা হয়েছে।\nআবার চেষ্টা করতে চাইলে নিচ থেকে দোকান খুলুন।",
                reply_markup=markup,
            )
        else:
            markup = admin_menu() if message.from_user.id in ADMIN_IDS else user_menu()
            welcome_text = (
                "👋 <b>স্বাগতম VPN SHOP এ!</b>\n\n"
                "🔐 সেরা মানের VPN একদম সহজে ও দ্রুত ডেলিভারিতে।\n"
                "নিচের বাটনে ক্লিক করে দোকান খুলুন এবং আপনার পছন্দের VPN অর্ডার করুন।\n\n"
                "❓ কোনো সমস্যায় পড়লে Help থেকে সাপোর্টে যোগাযোগ করুন।"
            )
            bot.send_message(message.chat.id, welcome_text, reply_markup=markup)
    except Exception:
        traceback.print_exc()
        bot.send_message(message.chat.id, "❌ কিছু একটা সমস্যা হয়েছে। এডমিনের সাথে যোগাযোগ করুন।")


# ================= ADMIN: TOTAL USER =================
@bot.message_handler(func=lambda m: m.text == "📊 TOTAL USER" and m.from_user.id in ADMIN_IDS)
def total_users(message):
    users = db_get("bot_users") or {}
    bot.send_message(message.chat.id, f"👥 <b>Total Users:</b> {len(users)}")


# ================= ADMIN: BROADCAST =================
@bot.message_handler(func=lambda m: m.text == "📢 BROADCAST" and m.from_user.id in ADMIN_IDS)
def broadcast_start(message):
    msg = bot.send_message(message.chat.id, "📢 Send me the message to broadcast to all users.")
    bot.register_next_step_handler(msg, broadcast_send)


def broadcast_send(message):
    users = db_get("bot_users") or {}
    status = bot.send_message(message.chat.id, f"📤 Sending to {len(users)} users...")
    sent, failed = 0, 0
    for uid in users:
        try:
            bot.copy_message(chat_id=int(uid), from_chat_id=message.chat.id, message_id=message.message_id)
            sent += 1
        except Exception:
            failed += 1
        time.sleep(0.05)  # stay under Telegram's rate limit
    bot.edit_message_text(
        f"✅ Broadcast Complete\nSent: {sent}\nFailed: {failed}",
        chat_id=message.chat.id, message_id=status.message_id,
    )


# ================= STEP 1: CREATE PAYMENT (auto-pay via gateway) =================
def start_payment(message, order_id):
    order = db_get(f"orders/{order_id}")
    if not order:
        bot.send_message(message.chat.id, "❌ অর্ডার খুঁজে পাওয়া যায়নি।")
        return
    if order.get("st") != "AwaitingPayment":
        bot.send_message(message.chat.id, "⚠️ এই অর্ডারের পেমেন্ট আগেই প্রসেস হয়ে গেছে অথবা মেয়াদ শেষ।")
        return

    amount = order.get("price")
    body = json.dumps({
        "cus_name": order.get("uname", "Customer"),
        "cus_email": f"user{order.get('uid')}@vpnshop.local",
        "amount": str(amount),
        "success_url": SUCCESS_REDIRECT_URL,
        "cancel_url": CANCEL_REDIRECT_URL,
        "meta_data": {"order_id": order_id, "uid": str(order.get("uid"))},
    })

    try:
        resp = ns_session.post(NS_CREATE_URL, headers=NS_HEADERS, data=body, timeout=15).json()
    except Exception:
        bot.send_message(message.chat.id, "❌ পেমেন্ট গেটওয়েতে সংযোগ করা যায়নি। একটু পরে চেষ্টা করুন।")
        return

    pay_url = resp.get("payment_url")
    if not pay_url:
        bot.send_message(message.chat.id, f"⚠️ পেমেন্ট লিংক তৈরি করা যায়নি।\nReason: {resp.get('message', 'Unknown error')}")
        return

    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("💳 Pay Now", url=pay_url))
    bot.send_message(
        message.chat.id,
        f"🛒 <b>{order.get('vpn')}</b> ({order.get('plan')})\n💰 Price: {amount} BDT\n\n"
        "পেমেন্ট সম্পন্ন করতে নিচের বাটনে ক্লিক করুন।",
        reply_markup=markup,
    )


# ================= STEP 2: VERIFY + DELIVER (auto-pay via gateway) =================
def handle_payment_success(message, transaction_id):
    if not transaction_id:
        bot.send_message(message.chat.id, "❌ ট্রানজেকশন আইডি পাওয়া যায়নি।")
        return

    body = json.dumps({"transaction_id": transaction_id})
    try:
        v = ns_session.post(NS_VERIFY_URL, headers=NS_HEADERS, data=body, timeout=15).json()
    except Exception:
        bot.send_message(message.chat.id, "❌ পেমেন্ট যাচাই করা যায়নি। এডমিনের সাথে যোগাযোগ করুন।")
        return

    if v.get("status") != "COMPLETED":
        bot.send_message(message.chat.id, f"⏳ পেমেন্ট এখনো সম্পন্ন হয়নি (status: {v.get('status')})।")
        return

    meta = v.get("metadata") or {}
    order_id = meta.get("order_id")
    order = db_get(f"orders/{order_id}") if order_id else None
    if not order:
        bot.send_message(message.chat.id, "❌ অর্ডার তথ্য পাওয়া যায়নি। এডমিনের সাথে যোগাযোগ করুন।")
        return

    if order.get("st") in ("Approved", "Pending"):
        bot.send_message(message.chat.id, "✅ এই অর্ডারটি ইতিমধ্যে প্রসেস করা হয়েছে।")
        return

    vpn_id = order.get("vpn_id")
    stock = db_get(f"vpns/{vpn_id}/stock") or {}
    now_bd = bd_now_str()

    if stock:
        stock_key = next(iter(stock))
        item = stock[stock_key]
        db_patch(f"orders/{order_id}", {
            "st": "Approved", "email": item["email"], "pass": item["pass"],
            "trx": v.get("transaction_id"), "method": v.get("payment_method"),
            "confirmedDate": now_bd,
        })
        db_delete(f"vpns/{vpn_id}/stock/{stock_key}")
        send_user_delivered(order, order_id, item, v)
    else:
        db_patch(f"orders/{order_id}", {
            "st": "Pending", "trx": v.get("transaction_id"),
            "method": v.get("payment_method"), "confirmedDate": now_bd,
        })
        send_user_pending(order, order_id, v)
        notify_admins(order, order_id, v, now_bd)


# ================= MESSAGE TEMPLATES =================
def send_user_pending(order, order_id, v):
    bot.send_message(order.get("uid"), (
        "📩 অর্ডার গ্রহণ করা হয়েছে\n\n"
        "আপনার অর্ডারটি সফলভাবে গ্রহণ করা হয়েছে। আমাদের টিম অর্ডারটি যাচাই করছে।\n\n"
        f"🆔 অর্ডার আইডি: #{order_id[-7:]}\n"
        f"🪙 VPN - {order.get('vpn')}\n"
        f"📦 PRICE - {order.get('price')}\n"
        f"💰 VALID - {order.get('plan')}\n"
        f"💳 METHOD : {(v.get('payment_method') or 'N/A').title()}\n"
        f"📱 TRANSACTION ID - {v.get('transaction_id')}\n\n"
        "আমাদের সাথে নিরাপদ লেনদেনের জন্য ধন্যবাদ।"
    ))


def send_user_delivered(order, order_id, item, v):
    bot.send_message(order.get("uid"), (
        "✅ অর্ডার সম্পন্ন হয়েছে!\n\n"
        f"🆔 অর্ডার আইডি: #{order_id[-7:]}\n"
        f"🪙 VPN - {order.get('vpn')}\n"
        f"📦 PRICE - {order.get('price')}\n"
        f"💰 VALID - {order.get('plan')}\n"
        f"💳 METHOD : {(v.get('payment_method') or 'N/A').title()}\n"
        f"📱 TRANSACTION ID - {v.get('transaction_id')}\n\n"
        "🔐 আপনার একাউন্ট তথ্য\n"
        f"Email/ID: {item['email']}\n"
        f"Password: {item['pass']}\n\n"
        "আমাদের সাথে নিরাপদ লেনদেনের জন্য ধন্যবাদ।"
    ))


def notify_admins(order, order_id, v, now_bd):
    uname = order.get("username")
    handle = f"@{uname}" if uname else order.get("uname", "Unknown")
    text = (
        f"🆕 NEW ORDER FROM {handle}\n"
        f"PRODUCT - {order.get('vpn')}\n"
        f"VALID - {order.get('plan')}\n"
        f"ORDER DATE & TIME : {now_bd}\n\n"
        f"Order ID: #{order_id[-7:]}\n"
        f"Price: {order.get('price')} BDT\n"
        f"Trx: {v.get('transaction_id')} ({v.get('payment_method')})\n\n"
        "⚠️ স্টক খালি ছিল — এডমিন প্যানেল থেকে ম্যানুয়ালি ডেলিভার করুন।"
    )
    for admin_id in ADMIN_IDS:
        try:
            bot.send_message(admin_id, text)
        except Exception:
            traceback.print_exc()


# =========================================================================
# ================= JSON API used by the Mini App (public/vpn.html) ======
# =========================================================================
# See the "SECURITY MODEL" section in the module docstring at the top of
# this file for how these are protected.

@app.route("/api/catalog")
def api_catalog():
    """Public: catalog data needed to render the store. Deliberately never
    includes stock credentials (only a count) or other users' orders."""
    vpns = db_get("vpns") or {}
    safe_vpns = {}
    for vid, v in vpns.items():
        safe_vpns[vid] = {
            "name": v.get("name"),
            "status": v.get("status", "ON"),
            "p1n": v.get("p1n"), "p1p": v.get("p1p"),
            "p2n": v.get("p2n"), "p2p": v.get("p2p"),
            "stock_count": len(v.get("stock") or {}),
        }
    payments = db_get("payments") or {}
    support_url = db_get("supportUrl") or ""
    return jsonify({"vpns": safe_vpns, "payments": payments, "supportUrl": support_url})


@app.route("/api/me/orders")
@require_auth
def api_my_orders(uid, is_admin, user):
    orders = db_get("orders") or {}
    mine = {oid: o for oid, o in orders.items()
            if str(o.get("uid")) == str(uid) and o.get("st") != "AwaitingPayment"}
    return jsonify(mine)


@app.route("/api/order", methods=["POST"])
@require_auth
def api_create_order(uid, is_admin, user):
    """Create a new order. The plan the client asks for is just a key
    ("p1" or "p2") - the price and plan name are always looked up here
    from the live vpns/ node, never taken from the client."""
    body = request.get_json(silent=True) or {}
    vpn_id = body.get("vpn_id")
    plan_key = body.get("plan")
    if plan_key not in ("p1", "p2") or not vpn_id:
        return jsonify({"error": "bad_request"}), 400

    vpn = db_get(f"vpns/{vpn_id}")
    if not vpn or vpn.get("status") == "OFF":
        return jsonify({"error": "vpn_unavailable"}), 400

    plan_name = vpn.get(f"{plan_key}n")
    plan_price = vpn.get(f"{plan_key}p")
    if not plan_name or plan_price is None:
        return jsonify({"error": "plan_unavailable"}), 400

    uname = user.get("first_name") or "Guest"
    username = user.get("username")

    order = {
        "vpn": vpn.get("name"), "vpn_id": vpn_id, "plan": plan_name, "price": plan_price,
        "uid": uid, "uname": uname, "username": username, "user": uname,
        "st": "AwaitingPayment",
    }
    result = db_push("orders", order)
    return jsonify({"order_id": result.get("name"), "vpn": order["vpn"], "plan": plan_name, "price": plan_price})


@app.route("/api/order/<order_id>/manual-pay", methods=["POST"])
@require_auth
def api_manual_pay(uid, is_admin, user, order_id):
    """User submits a self-reported bKash/Nagad transaction id. This only
    ever moves an order from AwaitingPayment -> Pending; it can never set
    Approved directly, and only the order's own owner can call it."""
    body = request.get_json(silent=True) or {}
    trx = (body.get("trx") or "").strip().upper()
    method = body.get("method") or ""
    if not trx:
        return jsonify({"error": "missing_trx"}), 400

    order = db_get(f"orders/{order_id}")
    if not order or str(order.get("uid")) != str(uid):
        return jsonify({"error": "not_found"}), 404
    if order.get("st") != "AwaitingPayment":
        return jsonify({"error": "wrong_state"}), 400

    date_str = datetime.now(BD_TZ).strftime("%d/%m/%Y %H:%M")
    db_patch(f"orders/{order_id}", {"trx": trx, "method": method, "st": "Pending", "date": date_str})
    return jsonify({"ok": True})


@app.route("/api/admin/data")
@require_admin
def api_admin_data(uid, user):
    orders = db_get("orders") or {}
    pending = {oid: o for oid, o in orders.items() if o.get("st") == "Pending"}
    vpns = db_get("vpns") or {}
    payments = db_get("payments") or {}
    support_url = db_get("supportUrl") or ""
    return jsonify({"pending": pending, "vpns": vpns, "payments": payments, "supportUrl": support_url})


@app.route("/api/admin/orders/<order_id>/deliver", methods=["POST"])
@require_admin
def api_admin_deliver(uid, user, order_id):
    body = request.get_json(silent=True) or {}
    stock_key = body.get("stock_key")

    order = db_get(f"orders/{order_id}")
    if not order:
        return jsonify({"error": "not_found"}), 404
    if order.get("st") != "Pending":
        return jsonify({"error": "wrong_state"}), 400

    vpn_id = order.get("vpn_id")
    stock = db_get(f"vpns/{vpn_id}/stock") or {}
    if not stock:
        return jsonify({"error": "no_stock"}), 400
    if not stock_key or stock_key not in stock:
        stock_key = next(iter(stock))
    item = stock[stock_key]

    now_bd = bd_now_str()
    db_patch(f"orders/{order_id}", {
        "st": "Approved", "email": item["email"], "pass": item["pass"], "confirmedDate": now_bd,
    })
    db_delete(f"vpns/{vpn_id}/stock/{stock_key}")

    try:
        send_user_delivered(order, order_id, item, {"payment_method": order.get("method"), "transaction_id": order.get("trx")})
    except Exception:
        traceback.print_exc()
    return jsonify({"ok": True})


@app.route("/api/admin/orders/<order_id>/reject", methods=["POST"])
@require_admin
def api_admin_reject(uid, user, order_id):
    order = db_get(f"orders/{order_id}")
    if not order:
        return jsonify({"error": "not_found"}), 404
    db_patch(f"orders/{order_id}", {"st": "Rejected"})
    try:
        bot.send_message(order.get("uid"), "⚠️ আপনার অর্ডারটি এডমিন কর্তৃক বাতিল করা হয়েছে।")
    except Exception:
        traceback.print_exc()
    return jsonify({"ok": True})


@app.route("/api/admin/stock", methods=["POST"])
@require_admin
def api_admin_add_stock(uid, user):
    body = request.get_json(silent=True) or {}
    vpn_id, email, pw = body.get("vpn_id"), body.get("email"), body.get("pass")
    if not (vpn_id and email and pw):
        return jsonify({"error": "bad_request"}), 400
    db_push(f"vpns/{vpn_id}/stock", {"email": email, "pass": pw})
    return jsonify({"ok": True})


@app.route("/api/admin/stock/<vpn_id>/<stock_key>", methods=["DELETE"])
@require_admin
def api_admin_delete_stock(uid, user, vpn_id, stock_key):
    db_delete(f"vpns/{vpn_id}/stock/{stock_key}")
    return jsonify({"ok": True})


@app.route("/api/admin/vpns", methods=["POST"])
@require_admin
def api_admin_add_vpn(uid, user):
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "bad_request"}), 400
    result = db_push("vpns", {"name": name, "status": "ON"})
    return jsonify({"ok": True, "id": result.get("name")})


@app.route("/api/admin/vpns/<vpn_id>", methods=["PATCH"])
@require_admin
def api_admin_update_vpn(uid, user, vpn_id):
    body = request.get_json(silent=True) or {}
    allowed = {k: v for k, v in body.items() if k in ("p1n", "p1p", "p2n", "p2p", "status")}
    if not allowed:
        return jsonify({"error": "bad_request"}), 400
    db_patch(f"vpns/{vpn_id}", allowed)
    return jsonify({"ok": True})


@app.route("/api/admin/vpns/<vpn_id>", methods=["DELETE"])
@require_admin
def api_admin_delete_vpn(uid, user, vpn_id):
    db_delete(f"vpns/{vpn_id}")
    return jsonify({"ok": True})


@app.route("/api/admin/payments", methods=["POST"])
@require_admin
def api_admin_add_payment(uid, user):
    body = request.get_json(silent=True) or {}
    name, num = body.get("name"), body.get("num")
    if not (name and num):
        return jsonify({"error": "bad_request"}), 400
    result = db_push("payments", {"name": name, "num": num})
    return jsonify({"ok": True, "id": result.get("name")})


@app.route("/api/admin/payments/<pay_id>", methods=["DELETE"])
@require_admin
def api_admin_delete_payment(uid, user, pay_id):
    db_delete(f"payments/{pay_id}")
    return jsonify({"ok": True})


@app.route("/api/admin/support-url", methods=["POST"])
@require_admin
def api_admin_set_support(uid, user):
    body = request.get_json(silent=True) or {}
    db_put("supportUrl", body.get("url", ""))
    return jsonify({"ok": True})


# ================= FLASK ROUTES (webhook + health check) =================
@app.route(f"/webhook/{BOT_TOKEN}", methods=["POST"])
def telegram_webhook():
    update = telebot.types.Update.de_json(request.get_data().decode("utf-8"))
    bot.process_new_updates([update])
    return "OK", 200


@app.route("/")
def home():
    # Opening the base URL shows the actual store (vpn.html)
    return send_from_directory(app.static_folder, "vpn.html")


@app.route("/health")
def health():
    # Lightweight route for the self-ping loop to hit every 5 minutes
    return "VPN Shop bot is alive", 200


def self_ping_loop():
    """
    Hits our own '/' health route every 5 minutes so Render always sees
    recent traffic and never spins the free instance down. Runs forever
    in a background thread - no external pinging service needed.
    """
    if not RENDER_EXTERNAL_URL:
        print("RENDER_EXTERNAL_URL not set - self-ping disabled (fine for local testing).")
        return
    while True:
        time.sleep(300)  # 5 minutes
        try:
            requests.get(RENDER_EXTERNAL_URL.rstrip("/") + "/health", timeout=10)
            print(f"[self-ping] OK at {datetime.now(BD_TZ).strftime('%H:%M:%S')}")
        except Exception as e:
            print(f"[self-ping] failed: {e}")


def register_webhook():
    if not RENDER_EXTERNAL_URL:
        print("RENDER_EXTERNAL_URL not set - skipping webhook registration (fine for local testing).")
        return
    try:
        bot.remove_webhook()
        time.sleep(1)
        bot.set_webhook(url=f"{RENDER_EXTERNAL_URL}/webhook/{BOT_TOKEN}")
        print(f"Webhook registered at {RENDER_EXTERNAL_URL}/webhook/{BOT_TOKEN}")
    except Exception:
        traceback.print_exc()


register_webhook()
threading.Thread(target=self_ping_loop, daemon=True).start()

if __name__ == "__main__":
    # Local dev only - Render runs this via gunicorn (see Procfile)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
