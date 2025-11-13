# Debt Management Snowball App

A minimal full-stack implementation of the snowball debt payoff concept. The project ships with a Flask backend, SQLite persistence, and a responsive interface that mirrors the provided UI mocks.

## Features

- Add unlimited debts and view them in a sortable table.
- Automatic snowball strategy summary (balance, minimums, payoff order, and projected months).
- Focus card for the next debt to attack and a quick "Pay off" action.
- Interactive debt payoff calculator for experimenting with balances, rates, and payments.
- Multi-step capture experience for adding debts on mobile.
- JSON API at `/api/debts` for integrating with other tools.

## Getting Started

1. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

2. **Run the development server**

   ```bash
   flask --app app run --debug
   ```

3. Visit `http://127.0.0.1:5000/` to use the dashboard or `http://127.0.0.1:5000/debts/new` for the multi-step form.

The SQLite database (`snowball.db`) is created automatically on first run.
