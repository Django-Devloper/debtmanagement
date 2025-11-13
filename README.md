# Debt Management Snowball App

A minimal full-stack implementation of the snowball debt payoff concept. The project ships with a Flask backend, SQLite persistence, and a responsive interface that mirrors the provided UI mocks.

## Features

- Secure email/password authentication with personal dashboards per user.
- Add unlimited debts tied to the logged-in profile and view them in a sortable table.
- Capture every income stream (salary, freelance, rental, etc.) and see the converted monthly cash flow alongside your minimum payments.
- Create savings goals (emergency funds, vacations, tuition, etc.) with optional timelines and see recommended monthly contributions to stay on target.
- Automatic snowball strategy summary (balance, minimums, payoff order, and projected months) that honors each user's extra-payment preference.
- Parallel avalanche strategy projection so every user can compare both payoff methods (snowball momentum vs. avalanche interest savings) and see how long each will take to reach debt freedom.
- Emergency fund insights calculated from your minimum payments so you know how much cushion to keep while eliminating debt.
- Focus card for the next debt to attack and a quick "Pay off" action.
- Interactive debt payoff calculator for experimenting with balances, rates, and payments.
- Multi-step capture experience for adding debts on mobile.
- Profile page to update your name, email, and monthly extra snowball contribution.
- Omni-channel JSON API (authenticated) for debts, incomes, savings goals, payoff strategies, and aggregated summaries to power other clients.

## API surface

Every endpoint requires an authenticated session (obtain via the regular login form or by attaching the session cookie in your client).

| Endpoint | Method(s) | Description |
| --- | --- | --- |
| `/api/v1/summary` | GET | Returns the complete financial snapshot (user profile, debts, incomes, goals, strategies, cash-flow insights). |
| `/api/v1/strategies` | GET | Snowball and avalanche payoff projections only. |
| `/api/v1/debts` | GET/POST | List debts or create a new debt (JSON body mirrors the dashboard form). |
| `/api/v1/debts/<id>` | DELETE | Remove a debt. |
| `/api/v1/incomes` | GET/POST | List income streams or add a new one. |
| `/api/v1/incomes/<id>` | DELETE | Remove an income entry. |
| `/api/v1/goals` | GET/POST | List or create savings goals with optional `target_date`. |
| `/api/v1/goals/<id>` | PATCH/DELETE | Update goal details/progress or delete the goal. |

The legacy `/api/debts` endpoint now returns the same snapshot as `/api/v1/summary` for backward compatibility.

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

> **Schema change note:** if you used an older build (before authentication) the app now auto-upgrades the `debts` table by adding the new `user_id` column on startup. Registering or logging in will automatically attach any legacy debts (those created prior to auth) to the account you signed into. Income tracking uses a brand-new table so the schema will be created automatically on first launch after pulling these changes. If you prefer to start fresh you can still delete `snowball.db` before launching the server.

The SQLite database (`snowball.db`) is created automatically on first run.
