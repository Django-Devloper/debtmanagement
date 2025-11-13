# Debt Management Snowball App

A minimal full-stack implementation of the snowball debt payoff concept. The project ships with a Flask backend, SQLite persistence, and a responsive interface that mirrors the provided UI mocks.

## Features

- Secure email/password authentication with personal dashboards per user.
- Add unlimited debts tied to the logged-in profile and view them in a sortable table.
- Automatic snowball strategy summary (balance, minimums, payoff order, and projected months) that honors each user's extra-payment preference.
- Focus card for the next debt to attack and a quick "Pay off" action.
- Interactive debt payoff calculator for experimenting with balances, rates, and payments.
- Multi-step capture experience for adding debts on mobile.
- Profile page to update your name, email, and monthly extra snowball contribution.
- JSON API at `/api/debts` (requires authentication) for integrating with other tools.

## Getting Started

1. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

2. **Run the development server**

   ```bash
   flask --app app run --debug
   ```

3. Visit `http://127.0.0.1:5000/register` to create an account, then log in at `/login` to access your dashboard. Use `/debts/new` for the multi-step form once signed in.

4. Manage your profile (name, email, and monthly extra payment) at `/profile` any time.

> **Schema change note:** if you used an older build (before authentication) the app now auto-upgrades the `debts` table by adding the new `user_id` column on startup. Registering or logging in will automatically attach any legacy debts (those created prior to auth) to the account you signed into. If you prefer to start fresh you can still delete `snowball.db` before launching the server.

The SQLite database (`snowball.db`) is created automatically on first run.
