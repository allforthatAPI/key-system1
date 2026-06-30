# Saturn — License Key System

A self-hosted license key system: per-user keys, HWID locking, subscription
time tracking, and an admin dashboard, deployable to Render with a GitHub repo.

---

## ⚠️ Read this first: "uncrackable" doesn't exist

No client-side license check is unbeatable — anyone willing to patch your
binary or intercept its memory can eventually bypass it. What this system
gives you instead is a **real security boundary on the server**: every key
validation is re-checked against the database (revocation, expiry, HWID
match) on every call, not just trusted once. The client-side pieces are a
deterrent layer, not the actual lock. See the comments at the top of the
C++/C# SDK files for specifics on hardening further.

---

## What's included

```
saturn-keysystem/
├── backend/              # Node.js + Express + PostgreSQL API and admin dashboard
│   ├── server.js
│   ├── db/                # schema, connection pool, admin-creation script
│   ├── routes/             # /api/validate (public), /api/admin/* (dashboard)
│   ├── middleware/         # JWT auth guard
│   ├── utils/keygen.js     # key generation + HMAC signing
│   └── public/index.html   # the Saturn dashboard (single-file frontend)
├── client-sdk/
│   ├── cpp/SaturnAuth.h     # drop into a C++ project
│   └── csharp/SaturnAuth.cs # drop into a C# project
├── render.yaml             # one-click Render deployment blueprint
└── README.md
```

### How HWID locking works (and where it lives)

**Both client and server**, as requested:

- **Client side** (`SaturnAuth.h` / `SaturnAuth.cs`): computes a hardware ID
  by hashing CPU ID + motherboard/disk serial + machine GUID with SHA-256.
  The raw hardware identifiers never leave the machine — only the hash is
  sent.
- **Server side** (`routes/validate.js`): on a key's *first* validation, the
  server locks that key permanently to the HWID it received. Every
  subsequent validation must present the same HWID, or it's rejected. This
  is the part that actually can't be bypassed without server access — even
  if someone patches the client to skip its own checks, the server will
  still reject a key being used from an unrecognized HWID, *unless* they
  also spoof the HWID being sent over the network to match a previously
  authorized one (which requires already owning a valid activated key).

You (the admin) can unlock a key from its bound device anytime from the
dashboard via **Reset HWID** — useful when a legitimate user upgrades their
PC.

---

## 1. Local setup (optional, to test before deploying)

You'll need Node.js 18+ and a PostgreSQL database (local or free cloud one).

```bash
cd backend
npm install
cp .env.example .env
# edit .env: set DATABASE_URL, JWT_SECRET, KEY_SIGNING_SECRET

npm run init-db                      # creates tables
node db/createAdmin.js admin yourpassword   # creates your first dashboard login

npm start
```

Visit `http://localhost:3000` — you'll see the Saturn login screen.

---

## 2. Deploy to Render (with GitHub)

### Step A — Push this folder to a GitHub repository
```bash
cd saturn-keysystem
git init
git add .
git commit -m "Saturn key system"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

### Step B — Create the Render services
The included `render.yaml` lets Render set everything up automatically:

1. Go to [render.com](https://dashboard.render.com) → **New** → **Blueprint**
2. Connect your GitHub repo
3. Render will detect `render.yaml` and provision:
   - A **Web Service** (`saturn-keysystem`) running the backend
   - A **PostgreSQL database** (`saturn-db`), automatically wired via `DATABASE_URL`
   - Random secure values auto-generated for `JWT_SECRET` and `KEY_SIGNING_SECRET`
4. Click **Apply** — Render builds and deploys.

*(If you'd rather not use the blueprint: create a Web Service manually with
root directory `backend`, build command `npm install`, start command
`npm start`, then create a PostgreSQL instance separately and paste its
connection string into the `DATABASE_URL` environment variable.)*

### Step C — Create your admin account on the live server
Render's free web services have an in-browser **Shell** tab. Open it and run:

```bash
node db/createAdmin.js admin yourSecurePassword
```

(Replace `admin` / `yourSecurePassword` with your real credentials.)

### Step D — Log in
Visit your Render URL (e.g. `https://saturn-keysystem.onrender.com`) and log
in with the admin account you just created. You'll see the dashboard:
generate keys, create users, add/reduce subscription time, view HWID
binding status, revoke keys, and more.

> Note: Render's free tier spins down after inactivity and takes ~30–60s to
> wake on the next request — fine for an admin dashboard, but be aware your
> *client software's* validation calls will see that same cold-start delay
> on a customer's first launch after idle time. Upgrade to a paid Render
> instance if that's not acceptable for your users.

---

## 3. Wire up your software (C++ or C#)

Copy the relevant file from `client-sdk/` into your project:

- **C++**: `client-sdk/cpp/SaturnAuth.h` — header-only, uses WinHTTP + BCrypt
  (link `winhttp.lib` and `bcrypt.lib`)
- **C#**: `client-sdk/csharp/SaturnAuth.cs` — needs the `System.Management`
  NuGet package for hardware queries

Then at your program's entry point:

**C++:**
```cpp
#include "SaturnAuth.h"

auto result = Saturn::ValidateKey(userEnteredKey, "https://saturn-keysystem.onrender.com");
if (!result.valid) {
    MessageBoxA(nullptr, result.error.c_str(), "License Error", MB_ICONERROR);
    return 1;
}
```

**C#:**
```csharp
var result = await Saturn.SaturnAuth.ValidateKeyAsync(userEnteredKey, "https://saturn-keysystem.onrender.com");
if (!result.Valid) {
    Console.WriteLine("License error: " + result.Error);
    Environment.Exit(1);
}
```

Both files have full usage examples and hardening notes at the bottom.

---

## 4. Day-to-day usage of the dashboard

- **Add User**: create a user record with display name, login username/password
- **Generate Keys**: choose quantity (1–500) and duration (or lifetime), optionally
  assign straight to a user; results show in a copyable list with a **Download as .txt** button
- **Per-key controls**: Add Time / Reduce Time (in days), Reset HWID, Revoke/Unrevoke, Delete
- **Search bar**: filters by name, username, or key string

---

## 5. Security notes worth knowing

- Admin passwords are hashed with bcrypt (cost factor 12); never stored in plaintext.
- Admin dashboard sessions use JWTs that expire after 12 hours.
- `/api/validate` is rate-limited (15 requests/min per IP) to slow down brute-force key guessing.
- Generated keys carry an HMAC checksum signed with `KEY_SIGNING_SECRET`, so malformed
  or randomly-guessed key strings fail before ever touching the database.
- Keep `JWT_SECRET` and `KEY_SIGNING_SECRET` private — anyone with `KEY_SIGNING_SECRET`
  could theoretically forge syntactically-valid-looking keys, though they'd still need
  one to actually exist in the database to pass `/api/validate`.
- Treat user passwords stored for the *software's own users* (the ones shown in the
  dashboard) as sensitive — they're bcrypt-hashed in the DB, but the dashboard shows
  a reset link rather than the plaintext, by design.
