# VPN SHOP - Secure Setup

## What changed (security)
The browser no longer talks to Firebase at all. Every action goes through
this backend (`app.py`), which verifies Telegram's signed `initData` before
trusting who is asking, and derives prices/permissions itself instead of
trusting the browser.

## 1. Fill in your secrets (as environment variables on Render, not in code)
- `BOT_TOKEN` - your Telegram bot token
- `NS_API_KEY`, `NS_SECRET_KEY`, `NS_BRAND_KEY` - from your nstopup dashboard
- `FIREBASE_DB_SECRET` - see step 2

## 2. Lock your Firebase Realtime Database
Firebase Console -> Realtime Database -> Rules -> paste:
```json
{
  "rules": { ".read": false, ".write": false }
}
```
Publish. This blocks the public browser completely.

Then get a Database Secret so the backend can still read/write:
Firebase Console -> Project Settings (gear icon) -> Service Accounts ->
"Database secrets" tab -> Add/Show secret -> copy it into the
`FIREBASE_DB_SECRET` environment variable on Render.

(If your project doesn't show that tab, Firebase has been nudging people
towards Admin SDK service accounts instead - if so, tell me and I'll swap
the backend over to use `firebase-admin` with a service account JSON
instead of the legacy secret. Functionally equivalent, just a different
setup step.)

## 3. Deploy to Render
1. Push this whole folder to a GitHub repo (keep the `public/` folder as-is)
2. Render -> New -> Web Service -> connect the repo
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `gunicorn app:app` (Procfile already has this)
5. Add the environment variables from step 1
6. Deploy - the app registers its own Telegram webhook automatically and
   serves the store at its own root URL. No separate hosting needed.

## 4. Test
- Open your bot in Telegram, tap "Open VPN Shop"
- Buy a plan -> Auto Pay -> pay -> should auto-deliver if stock exists
- As an admin account, you should see the extra "Admin" nav button and the
  📊 TOTAL USER / 📢 BROADCAST keyboard buttons in the bot chat

## Why this is safe now
- No Firebase API key/URL is exposed to anything the browser can write with
- Every write (approve order, add stock, change price, toggle a VPN on/off)
  happens in `app.py`, which re-checks the caller's real Telegram identity
  from the cryptographically signed `initData` on every single request
- Order price is always taken from the VPN's current price in the database,
  never from whatever the browser sends
- Stock passwords are never sent to a non-admin browser, and never even to
  the admin's browser - the bot DMs credentials straight to the buyer
