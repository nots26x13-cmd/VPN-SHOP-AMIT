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

## Payment now stays inside the web app
"Auto Pay" opens the nstopup checkout in an iframe inside `vpn.html`
instead of Telegram's separate in-app browser (`tg.openLink`). When the
gateway redirects to `success.html`/`cancel.html` (same domain as this
app), that page tells the web app the result directly, and a new backend
route (`/api/order/verify-transaction`) confirms the transaction and
delivers stock - the same server-side logic the old bot-deep-link path
used, just reachable straight from the browser now. Nothing about the
security model changed: the backend still re-verifies with nstopup and
still DMs credentials via the bot, never through the browser.

Caveat: some payment gateways refuse to render inside an iframe on
purpose (an `X-Frame-Options`/CSP header on *their* page, to prevent
clickjacking during card/PIN entry) - that's their server's decision, not
something fixable from this app's code. If nstopup's checkout page does
this, the iframe will just stay blank. There's a small "পেজ লোড না হলে
এখানে ক্লিক করে খুলুন" (open externally) link under the iframe as a
fallback for that case - test Auto Pay once after deploying to confirm
it renders for you.

## Manual payment + USD/BDT
Manual payment (Bkash/Nagad-style) is back alongside Auto Pay. Admin ->
VPN MGMT -> "Add Manual Method" now also asks for a currency: BDT or
Dollar. Pick Dollar and a "Dollar rate (in BDT)" field appears - that's
the exchange rate to use for that method.

VPN plan prices are still always stored/charged in BDT. When a customer
picks a Dollar-currency method at checkout, the app converts on the fly:
`USD to send = order price (BDT) / your rate`, and shows that instead of
the BDT amount. The transaction-ID confirmation step is unchanged; the
converted USD amount is just recorded alongside it for your reference
when you review pending orders.

Update the rate periodically since it's a fixed number you set, not a
live feed - use the ✏️ edit icon next to a method in Admin -> VPN MGMT ->
manual methods list to update its number and (for USD) its rate in place,
without deleting and re-adding it.

## If Auto Pay shows an error
Two real bugs got fixed here after comparing against a working demo bot
you shared for the same nstopup account:
- The request body was sending `"meta_data"` (with an underscore) but
  nstopup - and this app's own verify step - actually expects
  `"metadata"`. That mismatch is the most likely reason Auto Pay was
  failing.
- The API host briefly got changed to `gateway.nstopup.com` based on a
  guess; your demo bot confirms the correct host is `pay.nstopup.com`,
  and it's been reverted.

If it still fails, the backend logs the exact request it sent and
nstopup's exact raw response for every Auto Pay attempt - check your
Render service logs right after a failed attempt (`[nstopup create] ...`
lines). Other things worth checking:
- `NS_API_KEY` / `NS_SECRET_KEY` / `NS_BRAND_KEY` are set as real values
  in Render's environment variables (not the placeholder defaults)
- Your nstopup merchant account is fully activated
