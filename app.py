"""
VPN SHOP - Secure Backend (Bot + Website + API), ONE Render service
--------------------------------------------------------------------
SECURITY MODEL (read this before deploying):
  The old design let the browser talk to Firebase directly. That meant
  anyone could open DevTools and call the Firebase REST/JS SDK themselves
  to mark their own order "Approved", read every VPN account's plaintext
  password, or edit prices - because the "is this an admin?" check only
  existed in JavaScript (cosmetic), never enforced by a security rule.

  This version fixes that:
    - The browser NEVER talks to Firebase. It only calls this backend's
      /api/... routes over fetch().
    - Every request that must know "who is this" carries Telegram's raw
      signed `initData` string. The backend verifies its HMAC signature
      using the bot token (see verify_init_data) - this cannot be forged
      by a user, unlike the `initDataUnsafe` object.
    - Admin-only routes additionally check the verified Telegram user id
      against ADMIN_IDS - server-side, not client-side.
    - Prices are never trusted from the client: order creation looks up
      the VPN's real price on the server and ignores anything the
      browser sends for price.
    - Stock (email/password pairs) is only ever read/written by this
      backend - never sent to a non-admin browser, and only sent to the
      admin's browser as an email (never the password - the password is
      only ever DM'd straight to the buyer by the bot after delivery).

  LOCK YOUR FIREBASE RULES (do this once, in the Firebase console ->
  Realtime Database -> Rules):
      {
        "rules": { ".read": false, ".write": false }
      }
  This blocks ALL direct browser access. The backend still works
  because it authenticates its REST calls with your Database Secret
  (Firebase console -> Project Settings -> Service Accounts -> Database
  secrets) placed in the FIREBASE_DB_SECRET environment variable below.
  Admin/secret-authenticated access always bypasses ".read"/".write"
  rules, so locking the rules only blocks the public browser, not this
  backend.

DEPLOY ON RENDER:
  1. Push this folder to GitHub: app.py, requirements.txt, Procfile, public/
  2. Render -> New -> Web Service -> connect the repo
  3. Build Command: pip install -r requirements.txt
  4. Start Command: gunicorn app:app   (Procfile already sets this)
  5. Environment variables to set in Render's dashboard:
       BOT_TOKEN, NS_API_KEY, NS_SECRET_KEY, NS_BRAND_KEY, FIREBASE_DB_SECRET
     (Never commit real secrets into the GitHub repo itself.)
  6. Deploy. The app auto-registers its Telegram webhook and serves the
     Mini App at its own root URL - no other hosting needed.

IMPORTANT - Procfile uses --workers 1 (see Procfile) because the
Broadcast feature keeps short-lived state in this one process's memory.
"""

import os
import json
import time
import hmac
import hashlib
import threading
import traceback
import urllib.parse
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import wraps

import requests
import telebot
from telebot import types
from flask import Flask, request, jsonify, send_from_directory

# ================= CONFIG (env vars override these defaults) =================
BOT_TOKEN = os.environ.get("BOT_TOKEN", "8794536056:AAHiI20G3W2QSQIdfYKTUlpNd2RXHOIGzj8")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "vpnshop02_bot")

NS_API_KEY = os.environ.get("NS_API_KEY", "PUT_YOUR_NSTOPUP_API_KEY_HERE")
NS_SECRET_KEY = os.environ.get("NS_SECRET_KEY", "PUT_YOUR_NSTOPUP_SECRET_KEY_HERE")
NS_BRAND_KEY = os.environ.get("NS_BRAND_KEY", "7D7x6A6V56DtbYMxWUb15rIKRmh04iZaG0DU2XAzhd5UYaR12o")

NS_CREATE_URL = "https://pay.nstopup.com/api/payment/create"
NS_VERIFY_URL = "https://pay.nstopup.com/api/payment/verify"

FIREBASE_DB = os.environ.get("FIREBASE_DB", "https://vpn-store-s26x-default-rtdb.firebaseio.com")
# Database Secret (legacy auth) so the backend can read/write even after
# you lock the Realtime Database rules to block the public browser.
FIREBASE_DB_SECRET = os.environ.get("FIREBASE_DB_SECRET", "")

RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL")


def _default_url(env_name, path):
    v = os.environ.get(env_name)
    if v:
        return v
    if RENDER_EXTERNAL_URL:
        return RENDER_EXTERNAL_URL.rstrip("/") + path
    return "http://localhost:5000" + path


SUCCESS_REDIRECT_URL = _default_url("SUCCESS_REDIRECT_URL", "/success.html")
CANCEL_REDIRECT_URL = _default_url("CANCEL_REDIRECT_URL", "/cancel.html")
WEBAPP_URL = _default_url("WEBAPP_URL", "/")

ADMIN_IDS = [8505710811, 7940769450]
BD_TZ = ZoneInfo("Asia/Dhaka")

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML", threaded=True)
app = Flask(__name__, static_folder="public", static_url_path="")

fb_session = requests.Session()
ns_session = requests.Session()
NS_HEADERS = {
    "API-KEY": NS_API_KEY,
    "Content-Type": "application/json",
    "SECRET-KEY": NS_SECRET_KEY,
    "BRAND-KEY": NS_BRAND_KEY,
}


# ================= FIREBASE HELPERS (server-side only) =================
def _auth_suffix():
    return f"?auth={FIREBASE_DB_SECRET}" if FIREBASE_DB_SECRET else ""


def db_get(path):
    r = fb_session.get(f"{FIREBASE_DB}/{path}.json{_auth_suffix()}", timeout=10)
    r.raise_for_status()
    return r.json()


def db_patch(path, data):
    r = fb_session.patch(f"{FIREBASE_DB}/{path}.json{_auth_suffix()}", json=data, timeout=10)
    r.raise_for_status()
    return r.json()


def db_put(path, data):
    r = fb_session.put(f"{FIREBASE_DB}/{path}.json{_auth_suffix()}", json=data, timeout=10)
    r.raise_for_status()
    return r.json()


def db_push(path, data):
    r = fb_session.post(f"{FIREBASE_DB}/{path}.json{_auth_suffix()}", json=data, timeout=10)
    r.raise_for_status()
    return r.json().get("name")


def db_delete(path):
    fb_session.delete(f"{FIREBASE_DB}/{path}.json{_auth_suffix()}", timeout=10)


# ================= TIME HELPER (Bangladesh) =================
def bd_now_str():
    now = datetime.now(BD_TZ)
    time_part = now.strftime("%I:%M %p")
    if time_part.startswith("0"):
        time_part = time_part[1:]
    return f"{time_part} - {now.month}/{now.day}/{now.year}"


# ================= TELEGRAM initData VERIFICATION =================
def verify_init_data(init_data, max_age_seconds=86400):
    """Cryptographically verifies Telegram WebApp initData using the bot
    token, per Telegram's official algorithm. Returns the verified user
    dict on success, or None if the data is missing/forged/expired.
    This is the ONLY thing this backend trusts to know who is calling it -
    never trust a plain user_id sent in a JSON body."""
    if not init_data:
        return None
    try:
        pairs = dict(urllib.parse.parse_qsl(init_data, keep_blank_values=True))
        received_hash = pairs.pop("hash", None)
        if not received_hash:
            return None
        data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
        secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(computed_hash, received_hash):
            return None
        auth_date = int(pairs.get("auth_date", "0"))
        if time.time() - auth_date > max_age_seconds:
            return None
        return json.loads(pairs.get("user", "{}"))
    except Exception:
        return None


def _extract_init_data():
    if request.is_json:
        return (request.get_json(silent=True) or {}).get("initData", "")
    return request.form.get("initData", "") or request.headers.get("X-Init-Data", "")


def require_user(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = verify_init_data(_extract_init_data())
        if not user or "id" not in user:
            return jsonify({"error": "unauthorized"}), 401
        request.tg_user = user
        return f(*args, **kwargs)
    return wrapper


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = verify_init_data(_extract_init_data())
        if not user or user.get("id") not in ADMIN_IDS:
            return jsonify({"error": "forbidden"}), 403
        request.tg_user = user
        return f(*args, **kwargs)
    return wrapper


# ================= SHARED PAYMENT LOGIC (used by web + bot) =================
def create_payment_link_for_order(order_id):
    order = db_get(f"orders/{order_id}")
    if not order:
        return None, "Order not found"
    if order.get("st") != "AwaitingPayment":
        return None, "This order has already been processed"

    body = json.dumps({
        "amount": str(order.get("price")),
        "success_url": SUCCESS_REDIRECT_URL,
        "cancel_url": CANCEL_REDIRECT_URL,
        "metadata": {"order_id": order_id, "uid": str(order.get("uid"))},
    })
    try:
        raw = ns_session.post(NS_CREATE_URL, headers=NS_HEADERS, data=body, timeout=15)
    except Exception as e:
        print(f"[nstopup create] request failed: {e}")
        return None, "Could not reach payment gateway"

    # Log everything nstopup actually sent back - this is what tells you
    # WHY it failed (bad key, bad amount format, bad url, etc). Check your
    # Render logs after a failed "Auto Pay" attempt.
    print(f"[nstopup create] order={order_id} sent={body}")
    print(f"[nstopup create] status={raw.status_code} body={raw.text[:1000]}")

    try:
        resp = raw.json()
    except Exception:
        return None, "Could not reach payment gateway"

    pay_url = resp.get("payment_url") or resp.get("url")
    if not pay_url:
        return None, resp.get("message", "Unknown gateway error")
    return pay_url, None


def process_verified_payment(transaction_id):
    """Called after nstopup confirms a transaction. Delivers stock if
    available, otherwise marks Pending and pings the admins."""
    body = json.dumps({"transaction_id": transaction_id})
    try:
        v = ns_session.post(NS_VERIFY_URL, headers=NS_HEADERS, data=body, timeout=15).json()
    except Exception:
        return None, "Could not verify payment"

    if v.get("status") != "COMPLETED":
        return None, f"Payment not completed yet (status: {v.get('status')})"

    meta = v.get("metadata") or {}
    order_id = meta.get("order_id")
    order = db_get(f"orders/{order_id}") if order_id else None
    if not order:
        return None, "Order not found for this transaction"

    if order.get("st") in ("Approved", "Pending"):
        return order_id, None  # already processed, avoid double-delivery

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
        notify_admins_new_order(order, order_id, v, now_bd)

    return order_id, None


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


def send_user_rejected(order, order_id):
    bot.send_message(order.get("uid"), (
        f"❌ আপনার অর্ডার (#{order_id[-7:]}) বাতিল করা হয়েছে।\n"
        "বিস্তারিত জানতে সাপোর্টে যোগাযোগ করুন।"
    ))


def notify_admins_new_order(order, order_id, v, now_bd):
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


# ================= USER TRACKING =================
def save_user_once(tg_user_or_message):
    if hasattr(tg_user_or_message, "from_user"):
        uid = str(tg_user_or_message.from_user.id)
        name = tg_user_or_message.from_user.first_name or ""
        username = tg_user_or_message.from_user.username or ""
    else:
        uid = str(tg_user_or_message.get("id"))
        name = tg_user_or_message.get("first_name", "")
        username = tg_user_or_message.get("username", "")
    if db_get(f"bot_users/{uid}"):
        return False
    db_patch(f"bot_users/{uid}", {"name": name, "username": username, "joined": bd_now_str()})
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


# ================= BOT: /start =================
@bot.message_handler(commands=["start"])
def handle_start(message):
    save_user_once(message)
    parts = message.text.split(maxsplit=1)
    payload = parts[1] if len(parts) > 1 else ""

    try:
        if payload.startswith("pay_"):
            order_id = payload[len("pay_"):]
            pay_url, err = create_payment_link_for_order(order_id)
            if err:
                bot.send_message(message.chat.id, f"⚠️ {err}")
                return
            order = db_get(f"orders/{order_id}")
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton("💳 Pay Now", url=pay_url))
            bot.send_message(
                message.chat.id,
                f"🛒 <b>{order.get('vpn')}</b> ({order.get('plan')})\n💰 Price: {order.get('price')} BDT\n\n"
                "পেমেন্ট সম্পন্ন করতে নিচের বাটনে ক্লিক করুন।",
                reply_markup=markup,
            )
        elif payload.startswith("verify_"):
            transaction_id = payload[len("verify_"):]
            order_id, err = process_verified_payment(transaction_id)
            if err:
                bot.send_message(message.chat.id, f"⚠️ {err}")
        elif payload.startswith("cancel"):
            bot.send_message(
                message.chat.id,
                "⚠️ পেমেন্ট বাতিল করা হয়েছে।\nআবার চেষ্টা করতে চাইলে নিচ থেকে দোকান খুলুন।",
                reply_markup=admin_menu() if message.from_user.id in ADMIN_IDS else user_menu(),
            )
        else:
            welcome_text = (
                "👋 <b>স্বাগতম VPN SHOP এ!</b>\n\n"
                "🔐 সেরা মানের VPN একদম সহজে ও দ্রুত ডেলিভারিতে।\n"
                "নিচের বাটনে ক্লিক করে দোকান খুলুন এবং আপনার পছন্দের VPN অর্ডার করুন।\n\n"
                "❓ কোনো সমস্যায় পড়লে Help থেকে সাপোর্টে যোগাযোগ করুন।"
            )
            bot.send_message(
                message.chat.id, welcome_text,
                reply_markup=admin_menu() if message.from_user.id in ADMIN_IDS else user_menu(),
            )
    except Exception:
        traceback.print_exc()
        bot.send_message(message.chat.id, "❌ কিছু একটা সমস্যা হয়েছে। এডমিনের সাথে যোগাযোগ করুন।")


@bot.message_handler(func=lambda m: m.text == "📊 TOTAL USER" and m.from_user.id in ADMIN_IDS)
def total_users(message):
    users = db_get("bot_users") or {}
    bot.send_message(message.chat.id, f"👥 <b>Total Users:</b> {len(users)}")


@bot.message_handler(func=lambda m: m.text == "📢 BROADCAST" and m.from_user.id in ADMIN_IDS)
def broadcast_prompt(message):
    msg = bot.send_message(message.chat.id, "📢 যা broadcast করতে চান পাঠান — text, photo, video, document, যেকোনো টাইপ চলবে।")
    bot.register_next_step_handler(msg, do_broadcast)


def do_broadcast(message):
    if message.from_user.id not in ADMIN_IDS:
        return
    users = db_get("bot_users") or {}
    status = bot.send_message(message.chat.id, f"⏳ Broadcasting to {len(users)} users...")
    sent, failed = 0, 0
    for uid in users:
        try:
            bot.copy_message(chat_id=int(uid), from_chat_id=message.chat.id, message_id=message.message_id)
            sent += 1
        except Exception:
            failed += 1
        time.sleep(0.05)
    bot.edit_message_text(f"✅ Broadcast Complete\nSent: {sent}\nFailed: {failed}",
                           chat_id=message.chat.id, message_id=status.message_id)


# ================================================================
# PUBLIC API (no auth needed - safe, non-sensitive catalog data only)
# ================================================================
@app.route("/api/vpns", methods=["GET"])
def api_vpns():
    vpns = db_get("vpns") or {}
    out = []
    for vid, v in vpns.items():
        out.append({
            "id": vid, "name": v.get("name"), "status": v.get("status", "ON"),
            "p1n": v.get("p1n"), "p1p": v.get("p1p"),
            "p2n": v.get("p2n"), "p2p": v.get("p2p"),
            "stock_count": len(v.get("stock") or {}),
        })
    return jsonify(out)


@app.route("/api/payments", methods=["GET"])
def api_payments():
    payments = db_get("payments") or {}
    return jsonify([
        {"id": pid, "name": p.get("name"), "num": p.get("num"),
         "currency": p.get("currency", "BDT"), "rate": p.get("rate")}
        for pid, p in payments.items()
    ])


@app.route("/api/support", methods=["GET"])
def api_support():
    return jsonify({"url": db_get("supportUrl") or ""})


# ================================================================
# USER API (requires verified initData, any Telegram user)
# ================================================================
@app.route("/api/whoami", methods=["POST"])
@require_user
def api_whoami():
    u = request.tg_user
    save_user_once(u)
    return jsonify({
        "id": u.get("id"), "name": u.get("first_name", "Guest"),
        "username": u.get("username"), "is_admin": u.get("id") in ADMIN_IDS,
    })


@app.route("/api/order/create", methods=["POST"])
@require_user
def api_order_create():
    u = request.tg_user
    data = request.get_json(silent=True) or {}
    vpn_id, plan_name = data.get("vpn_id"), data.get("plan")

    vpn = db_get(f"vpns/{vpn_id}") if vpn_id else None
    if not vpn or vpn.get("status") == "OFF":
        return jsonify({"error": "VPN not available"}), 400

    price = None
    if vpn.get("p1n") == plan_name:
        price = vpn.get("p1p")
    elif vpn.get("p2n") == plan_name:
        price = vpn.get("p2p")
    if price is None:
        return jsonify({"error": "Invalid plan"}), 400

    order_id = db_push("orders", {
        "vpn": vpn.get("name"), "vpn_id": vpn_id, "plan": plan_name, "price": price,
        "uid": u.get("id"), "uname": u.get("first_name", "Customer"),
        "username": u.get("username"), "user": u.get("first_name", "Customer"),
        "st": "AwaitingPayment",
    })
    return jsonify({"order_id": order_id, "price": price})


@app.route("/api/order/pay", methods=["POST"])
@require_user
def api_order_pay():
    data = request.get_json(silent=True) or {}
    order_id = data.get("order_id")
    order = db_get(f"orders/{order_id}") if order_id else None
    if not order or order.get("uid") != request.tg_user.get("id"):
        return jsonify({"error": "Order not found"}), 404

    pay_url, err = create_payment_link_for_order(order_id)
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"payment_url": pay_url})


@app.route("/api/order/verify-transaction", methods=["POST"])
@require_user
def api_order_verify_transaction():
    """Lets the Mini App itself confirm a payment (used when the gateway's
    checkout page is embedded in an in-app iframe instead of opening the
    Telegram deep-link back to the bot). Does exactly what the bot's
    `verify_<trx>` /start payload already does - re-checks the transaction
    with nstopup server-side and is idempotent, so it's safe even if the
    bot deep-link path also fires for the same transaction."""
    data = request.get_json(silent=True) or {}
    transaction_id = data.get("transaction_id")
    if not transaction_id:
        return jsonify({"error": "transaction_id required"}), 400

    order_id, err = process_verified_payment(transaction_id)
    if err:
        return jsonify({"error": err}), 400

    order = db_get(f"orders/{order_id}") if order_id else None
    if not order or order.get("uid") != request.tg_user.get("id"):
        # Don't let one user's browser confirm/read another user's order
        return jsonify({"error": "Order not found"}), 404

    return jsonify({"ok": True, "order_id": order_id, "status": order.get("st")})


@app.route("/api/order/pay-manual", methods=["POST"])
@require_user
def api_order_pay_manual():
    data = request.get_json(silent=True) or {}
    order_id, method, trx = data.get("order_id"), data.get("method"), data.get("trx")
    currency, sent_amount = data.get("currency"), data.get("sent_amount")
    order = db_get(f"orders/{order_id}") if order_id else None
    if not order or order.get("uid") != request.tg_user.get("id"):
        return jsonify({"error": "Order not found"}), 404
    if order.get("st") != "AwaitingPayment":
        return jsonify({"error": "Already processed"}), 400
    if not trx:
        return jsonify({"error": "Transaction ID required"}), 400

    patch = {"st": "Pending", "method": method, "trx": trx.upper(), "date": bd_now_str()}
    if currency:
        patch["pay_currency"] = currency
    if sent_amount:
        patch["pay_sent_amount"] = sent_amount
    db_patch(f"orders/{order_id}", patch)
    return jsonify({"ok": True})


@app.route("/api/orders/mine", methods=["POST"])
@require_user
def api_orders_mine():
    uid = request.tg_user.get("id")
    orders = db_get("orders") or {}
    mine = []
    for oid, o in orders.items():
        if o.get("uid") == uid and o.get("st") != "AwaitingPayment":
            mine.append({**o, "id": oid})
    mine.sort(key=lambda o: o.get("confirmedDate") or o.get("date") or "", reverse=True)
    return jsonify(mine)


# ================================================================
# ADMIN API (requires verified initData AND id in ADMIN_IDS)
# ================================================================
@app.route("/api/admin/orders/pending", methods=["POST"])
@require_admin
def api_admin_pending():
    orders = db_get("orders") or {}
    return jsonify([{**o, "id": oid} for oid, o in orders.items() if o.get("st") == "Pending"])


@app.route("/api/admin/stock/list", methods=["POST"])
@require_admin
def api_admin_stock_list():
    vpns = db_get("vpns") or {}
    out = {}
    for vid, v in vpns.items():
        stock = v.get("stock") or {}
        out[vid] = {"name": v.get("name"), "items": [{"key": k, "email": s["email"]} for k, s in stock.items()]}
    return jsonify(out)


@app.route("/api/admin/stock/add", methods=["POST"])
@require_admin
def api_admin_stock_add():
    data = request.get_json(silent=True) or {}
    vpn_id, email, password = data.get("vpn_id"), data.get("email"), data.get("pass")
    if not (vpn_id and email and password):
        return jsonify({"error": "Missing fields"}), 400
    db_push(f"vpns/{vpn_id}/stock", {"email": email, "pass": password})
    return jsonify({"ok": True})


@app.route("/api/admin/stock/delete", methods=["POST"])
@require_admin
def api_admin_stock_delete():
    data = request.get_json(silent=True) or {}
    db_delete(f"vpns/{data.get('vpn_id')}/stock/{data.get('stock_key')}")
    return jsonify({"ok": True})


@app.route("/api/admin/order/approve", methods=["POST"])
@require_admin
def api_admin_order_approve():
    data = request.get_json(silent=True) or {}
    order_id, stock_key = data.get("order_id"), data.get("stock_key")
    order = db_get(f"orders/{order_id}")
    if not order:
        return jsonify({"error": "Order not found"}), 404
    vpn_id = order.get("vpn_id")
    item = db_get(f"vpns/{vpn_id}/stock/{stock_key}")
    if not item:
        return jsonify({"error": "Stock item not found"}), 404

    db_patch(f"orders/{order_id}", {"st": "Approved", "email": item["email"], "pass": item["pass"]})
    db_delete(f"vpns/{vpn_id}/stock/{stock_key}")
    send_user_delivered(order, order_id, item, {"payment_method": order.get("method"), "transaction_id": order.get("trx")})
    return jsonify({"ok": True})


@app.route("/api/admin/order/reject", methods=["POST"])
@require_admin
def api_admin_order_reject():
    data = request.get_json(silent=True) or {}
    order_id = data.get("order_id")
    order = db_get(f"orders/{order_id}")
    if not order:
        return jsonify({"error": "Order not found"}), 404
    db_patch(f"orders/{order_id}", {"st": "Rejected"})
    send_user_rejected(order, order_id)
    return jsonify({"ok": True})


@app.route("/api/admin/vpn/add", methods=["POST"])
@require_admin
def api_admin_vpn_add():
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    if not name:
        return jsonify({"error": "Name required"}), 400
    vpn_id = db_push("vpns", {"name": name, "status": "ON"})
    return jsonify({"id": vpn_id})


@app.route("/api/admin/vpn/update", methods=["POST"])
@require_admin
def api_admin_vpn_update():
    data = request.get_json(silent=True) or {}
    vpn_id = data.get("vpn_id")
    db_patch(f"vpns/{vpn_id}", {
        "p1n": data.get("p1n", ""), "p1p": data.get("p1p", ""),
        "p2n": data.get("p2n", ""), "p2p": data.get("p2p", ""),
    })
    return jsonify({"ok": True})


@app.route("/api/admin/vpn/toggle", methods=["POST"])
@require_admin
def api_admin_vpn_toggle():
    data = request.get_json(silent=True) or {}
    db_patch(f"vpns/{data.get('vpn_id')}", {"status": "ON" if data.get("on") else "OFF"})
    return jsonify({"ok": True})


@app.route("/api/admin/vpn/delete", methods=["POST"])
@require_admin
def api_admin_vpn_delete():
    data = request.get_json(silent=True) or {}
    db_delete(f"vpns/{data.get('vpn_id')}")
    return jsonify({"ok": True})


@app.route("/api/admin/payment/add", methods=["POST"])
@require_admin
def api_admin_payment_add():
    data = request.get_json(silent=True) or {}
    name, num = data.get("name"), data.get("num")
    currency = (data.get("currency") or "BDT").upper()
    if currency not in ("BDT", "USD"):
        currency = "BDT"
    if not (name and num):
        return jsonify({"error": "Missing fields"}), 400

    rate = None
    if currency == "USD":
        try:
            rate = float(data.get("rate"))
        except (TypeError, ValueError):
            rate = None
        if not rate or rate <= 0:
            return jsonify({"error": "Valid dollar rate (in BDT) required"}), 400

    record = {"name": name, "num": num, "currency": currency}
    if rate:
        record["rate"] = rate
    pid = db_push("payments", record)
    return jsonify({"id": pid})


@app.route("/api/admin/payment/update", methods=["POST"])
@require_admin
def api_admin_payment_update():
    data = request.get_json(silent=True) or {}
    pid = data.get("payment_id")
    payment = db_get(f"payments/{pid}") if pid else None
    if not payment:
        return jsonify({"error": "Payment method not found"}), 404

    patch = {}
    num = data.get("num")
    if num:
        patch["num"] = num

    if payment.get("currency") == "USD":
        try:
            rate = float(data.get("rate"))
        except (TypeError, ValueError):
            rate = None
        if not rate or rate <= 0:
            return jsonify({"error": "Valid dollar rate (in BDT) required"}), 400
        patch["rate"] = rate

    if not patch:
        return jsonify({"error": "Nothing to update"}), 400

    db_patch(f"payments/{pid}", patch)
    return jsonify({"ok": True})


@app.route("/api/admin/payment/delete", methods=["POST"])
@require_admin
def api_admin_payment_delete():
    data = request.get_json(silent=True) or {}
    db_delete(f"payments/{data.get('payment_id')}")
    return jsonify({"ok": True})


@app.route("/api/admin/support/set", methods=["POST"])
@require_admin
def api_admin_support_set():
    data = request.get_json(silent=True) or {}
    db_put("supportUrl", data.get("url", ""))
    return jsonify({"ok": True})


@app.route("/api/admin/users/count", methods=["POST"])
@require_admin
def api_admin_users_count():
    users = db_get("bot_users") or {}
    return jsonify({"count": len(users)})


# ================================================================
# STATIC PAGES + TELEGRAM WEBHOOK + HEALTH
# ================================================================
@app.route("/")
def home():
    return send_from_directory(app.static_folder, "vpn.html")


@app.route("/health")
def health():
    return "VPN Shop bot is alive", 200


@app.route(f"/webhook/{BOT_TOKEN}", methods=["POST"])
def telegram_webhook():
    update = telebot.types.Update.de_json(request.get_data().decode("utf-8"))
    bot.process_new_updates([update])
    return "OK", 200


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


def self_ping_loop():
    if not RENDER_EXTERNAL_URL:
        print("RENDER_EXTERNAL_URL not set - self-ping disabled (fine for local testing).")
        return
    while True:
        time.sleep(300)
        try:
            requests.get(RENDER_EXTERNAL_URL.rstrip("/") + "/health", timeout=10)
            print(f"[self-ping] OK at {datetime.now(BD_TZ).strftime('%H:%M:%S')}")
        except Exception as e:
            print(f"[self-ping] failed: {e}")


register_webhook()
threading.Thread(target=self_ping_loop, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
