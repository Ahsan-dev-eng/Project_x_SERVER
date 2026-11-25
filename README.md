# MediMart Backend

Node/Express API for the MediMart medicine e-commerce platform. Serves the
`my-app` React frontend on `http://localhost:3001`.

## Project layout

```
index.js                  App wiring: middleware, DB connection, route mounting
models/index.js           Mongoose schemas + models
middleware/
  firebase.js             Firebase Admin SDK init + ID token / legacy JWT resolution
  auth.js                 requireAuth, requireAdmin, requireOwnerOrAdmin
  rateLimiter.js          Rate limiters for auth / order / booking / payment / review
  validators.js           express-validator chains (400 { error } responses)
routes/
  auth.js                 /login, /users, /users/me, /users/admin, /users/:email
  catalog.js              medicines, doctors, reviews, articles, categories
  appointments.js         appointment booking, rescheduling, payment, cancellation
  commerce.js             cart, orders, payments, vouchers, admin stats
  assistant.js            /chat (Gemini)
scripts/
  smokeTest.js            End-to-end auth / role / validation smoke test
  verifyModules.js        Structural check that every module exports what it should
  checkContract.js        Verifies the frontend endpoints.js is fully covered
  listRoutes.js           Prints every registered route
  checkFirebaseSetup.js   Validates the service account key without printing secrets
  listUserRoles.js        Lists database users and their roles
```

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create your local env file:

   ```bash
   cp .env.example .env.local
   ```

   Fill in `MONGODB_URI`, `JWT_SECRET` and `API_KEY`.
   Generate a strong JWT secret with:

   ```bash
   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
   ```

3. **Firebase Admin credentials** (required for native Firebase ID token
   verification):

   - Download a service account key for the Firebase project.
   - Save it as `serviceAccountKey.json` in the backend root. It is git-ignored
     and must never be committed.
   - `GOOGLE_APPLICATION_CREDENTIALS=./serviceAccountKey.json` is already set in
     `.env.local`.
   - For deployments, set `FIREBASE_SERVICE_ACCOUNT` to the service account JSON
     instead (it takes precedence over the file path).

   Without credentials the server still starts, but `/login` fails closed with
   `503` and Firebase ID tokens cannot be verified.

## Authentication model

The backend accepts **two** credential types during the migration to native
Firebase ID tokens:

1. **Firebase ID token** - verified with `admin.auth().verifyIdToken()`.
2. **Legacy session JWT** - issued by `POST /login`, signed with `JWT_SECRET`.

`POST /login` now **verifies the Firebase ID token before** issuing a session
JWT, and rejects the request when the token's email does not match the supplied
email.

Admin privileges are always read from the MongoDB `usersInfo` collection
(`role === 'Admin'`). Client supplied flags - including the `admin` field
returned by `/login` - are never trusted for authorization.

To switch the frontend over to native Firebase ID tokens, set:

```
REACT_APP_AUTH_MODE=firebase
```

in the frontend `.env.local`.

### Bootstrap the first admin

`POST /users` always creates users with the role `User`; a client can never
self-elevate. Promote the first admin directly in MongoDB:

```js
db.usersInfo.updateOne({ email: "you@example.com" }, { $set: { role: "Admin" } })
```

Afterwards use `PUT /users/admin` (admin only) to promote others.

## Scripts

```bash
npm start            # start the API on port 3001 (override with PORT)
npm test             # run the smoke test suite
npm run verify       # module structure + frontend contract checks
npm run routes       # list every registered route
npm run firebase:check  # validate the service account key (never prints secrets)
npm run users        # list database users and their roles
```

## Environment variables

See `.env.example` for the full list. The most important ones:

| Variable | Purpose |
| --- | --- |
| `MONGODB_URI` | MongoDB Atlas connection string |
| `JWT_SECRET` | Secret for the legacy session JWTs (min. 32 chars) |
| `API_KEY` | Gemini API key for `/chat` |
| `CLIENT_ORIGIN` | Comma-separated list of allowed browser origins |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to the service account key file |
| `FIREBASE_SERVICE_ACCOUNT` | Service account JSON (deployment alternative) |
| `PORT` | HTTP port (defaults to `3001`) |
| `TRUST_PROXY` | Number of proxy hops to trust for client IPs |
