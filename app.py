"""
VPN SHOP - Bot + Website, ONE Render service
------------------------------------------------------
This single Flask app now serves everything:
  - /             -> the Mini App store (public/vpn.html)
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

Faster than polling: Telegram pushes updates straight to this app instead
of constantly asking "any new messages?". Also reuses HTTP connections
(requests.Session) to Firebase + nstopup so each call doesn't pay a fresh
TCP/TLS handshake.

DEPLOY ON RENDER:
  1. Push this whole folder (app.py, requirements.txt, Procfile, public/)
     to a GitHub repo
  2. On Render: New -> Web Service -> connect the repo
  3. Environment: Python 3
  4. Build Command:  pip install -r requirements.txt
  5. Start Command:  gunicorn app:app  (Procfile already sets this)
  6. Add Environment Variables (Render dashboard -> Environment):
        BOT_TOKEN, NS_API_KEY, NS_SECRET_KEY, NS_BRAND_KEY
     (Don't hardcode secrets in code that goes on GitHub - use env vars.)
     You do NOT need to set WEBAPP_URL / SUCCESS_REDIRECT_URL /
     CANCEL_REDIRECT_URL - they're built automatically from Render's own
     URL since this app now serves those pages itself.
  7. Deploy. The app auto-registers itself as the Telegram webhook on
     startup using Render's URL - no manual step needed.

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
import threading
import traceback
from datetime import datetime
from zoneinfo import ZoneInfo

import requests
import telebot
from telebot import types
from flask import Flask, request, send_from_directory

# ================= CONFIG (env vars override these defaults) =================
BOT_TOKEN = os.environ.get("BOT_TOKEN", "8794536056:AAHiI20G3W2QSQIdfYKTUlpNd2RXHOIGzj8")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "vpnshop02_bot")

NS_API_KEY = os.environ.get("NS_API_KEY", "hxOqfq2kGekPhPqfscp8oZRRjxcHXxU9mWyVTAdJPQ6yV68wdg")
NS_SECRET_KEY = os.environ.get("NS_SECRET_KEY", "hxOqfq2kGekPhPqfscp8oZRRjxcHXxU9mWyVTAdJPQ6yV68wdg")
NS_BRAND_KEY = os.environ.get("NS_BRAND_KEY", "hxOqfq2kGekPhPqfscp8oZRRjxcHXxU9mWyVTAdJPQ6yV68wdg")

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

# ================= FIREBASE HELPERS =================
def db_get(path):
    r = fb_session.get(f"{FIREBASE_DB}/{path}.json", timeout=10)
    r.raise_for_status()
    return r.json()


def db_patch(path, data):
    r = fb_session.patch(f"{FIREBASE_DB}/{path}.json", json=data, timeout=10)
    r.raise_for_status()
    return r.json()


def db_delete(path):
    fb_session.delete(f"{FIREBASE_DB}/{path}.json", timeout=10)


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
def broadcast_prompt(message):
    msg = bot.send_message(
        message.chat.id,
        "📢 যা broadcast করতে চান পাঠান — text, photo, video, document, যেকোনো টাইপ চলবে।",
    )
    bot.register_next_step_handler(msg, do_broadcast)


def do_broadcast(message):
    if message.from_user.id not in ADMIN_IDS:
        return
    users = db_get("bot_users") or {}
    total = len(users)
    status = bot.send_message(message.chat.id, f"⏳ Broadcasting to {total} users...")
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


# ================= STEP 1: CREATE PAYMENT =================
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


# ================= STEP 2: VERIFY + DELIVER =================
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
