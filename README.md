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
- Omni-channel JSON API protected by JWT bearer tokens for debts, incomes, savings goals, payoff strategies, and aggregated summaries to power other clients.
- Built-in Swagger UI at `/api/docs` so you can explore, test, and share the authenticated API contract without extra tooling.

## API surface

Every endpoint requires a valid JWT bearer token. Obtain a token by POSTing valid credentials to `/api/v1/auth/token`, then include the header `Authorization: Bearer <token>` with each subsequent request. Tokens expire after 12 hours; simply request a new token when needed.

| Endpoint | Method(s) | Description |
| --- | --- | --- |
| `/api/v1/auth/token` | POST | Exchange email/password credentials for a short-lived JWT token. |
| `/api/v1/summary` | GET | Returns the complete financial snapshot (user profile, debts, incomes, goals, strategies, cash-flow insights). |
| `/api/v1/strategies` | GET | Snowball and avalanche payoff projections only. |
| `/api/v1/debts` | GET/POST | List debts or create a new debt (JSON body mirrors the dashboard form). |
| `/api/v1/debts/<id>` | DELETE | Remove a debt. |
| `/api/v1/incomes` | GET/POST | List income streams or add a new one. |
| `/api/v1/incomes/<id>` | DELETE | Remove an income entry. |
| `/api/v1/goals` | GET/POST | List or create savings goals with optional `target_date`. |
| `/api/v1/goals/<id>` | PATCH/DELETE | Update goal details/progress or delete the goal. |

The legacy `/api/debts` endpoint now returns the same snapshot as `/api/v1/summary` for backward compatibility and is also JWT-protected.

### Interactive docs

- **Swagger UI:** `http://127.0.0.1:5000/api/docs`
- **Raw OpenAPI JSON:** `http://127.0.0.1:5000/api/docs.json`

Sign in to the web app, grab a token via `/api/v1/auth/token`, then use the "Authorize" button in Swagger UI to try every endpoint with your user-scoped data.

### Authentication & headers

1. Register via the UI (or an admin tool) to create credentials.
2. Request a token:

   ```bash
   curl -X POST http://127.0.0.1:5000/api/v1/auth/token \
     -H "Content-Type: application/json" \
     -d '{"email": "avery@example.com", "password": "secret"}'
   ```

   ```json
   {
     "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "token_type": "Bearer",
     "expires_in": 43200
   }
   ```

3. Attach the header `Authorization: Bearer <access_token>` to every API request.

The APIs respond with `401 Unauthorized` if the token is missing/invalid/expired and `404 Not Found` if the referenced resource does not belong to the authenticated user.

### Common payloads

All JSON bodies follow snake_case fields:

```jsonc
// POST /api/v1/auth/token
{
  "email": "avery@example.com",
  "password": "secret"
}

// POST /api/v1/debts
{
  "debt_type": "credit_card",
  "creditor": "Amex Blue",
  "outstanding_amount": 5400.0,
  "interest_rate": 19.99,
  "minimum_due": 135.0,
  "emi": 220.0
}

// POST /api/v1/incomes
{
  "source": "Full-time Salary",
  "amount": 6200.0,
  "frequency": "monthly"
}

// POST /api/v1/goals
{
  "name": "Emergency fund",
  "target_amount": 12000.0,
  "target_date": "2025-12-31",
  "current_amount": 4000.0
}
```

### Response shapes

`GET /api/v1/summary` bundles every planner primitive for an omni-channel client:

```jsonc
{
  "api_version": 1,
  "generated_at": "2024-05-01T14:33:17.234Z",
  "user": {
    "id": 7,
    "name": "Avery",
    "email": "avery@example.com",
    "monthly_extra_payment": 200.0
  },
  "cash_flow": {
    "total_income": 7800.0,
    "total_minimums": 1830.0,
    "net_after_minimums": 5970.0,
    "progress_percent": 25.0
  },
  "debts": [/* same objects returned by GET /api/v1/debts */],
  "incomes": [/* same objects returned by GET /api/v1/incomes */],
  "goals": [/* same objects returned by GET /api/v1/goals */],
  "strategies": {
    "snowball": {
      "total_balance": 12800.0,
      "projected_months": 27,
      "payoff_order": [
        {"creditor": "Amex Blue", "months": 6},
        {"creditor": "Student Loan", "months": 21}
      ]
    },
    "avalanche": {
      "total_balance": 12800.0,
      "projected_months": 24,
      "payoff_order": [
        {"creditor": "Student Loan", "months": 12},
        {"creditor": "Amex Blue", "months": 12}
      ]
    }
  },
  "insights": {
    "recommended_emergency_fund": 3900.0,
    "emergency_gap": 1000.0,
    "goal_savings_total": 2900.0,
    "goal_count": 2
  }
}
```

Collection endpoints (`/debts`, `/incomes`, `/goals`) return arrays of objects with consistent `id` values plus computed helpers (e.g., `monthly_amount` on incomes or `recommended_monthly` on goals). Update/delete endpoints return `{ "status": "ok" }` on success.

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
