import math
from dataclasses import dataclass
from datetime import datetime
from typing import List, Tuple

from flask import Flask, redirect, render_template, request, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///snowball.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "snowball-secret"

db = SQLAlchemy(app)


class Debt(db.Model):
    __tablename__ = "debts"

    id = db.Column(db.Integer, primary_key=True)
    debt_type = db.Column(db.String(120), nullable=False)
    creditor = db.Column(db.String(120), nullable=False)
    outstanding_amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    emi = db.Column(db.Float, nullable=False)
    minimum_due = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def as_dict(self):
        return {
            "id": self.id,
            "debt_type": self.debt_type,
            "creditor": self.creditor,
            "outstanding_amount": self.outstanding_amount,
            "interest_rate": self.interest_rate,
            "emi": self.emi,
            "minimum_due": self.minimum_due,
        }


@dataclass
class SnowballSummary:
    total_balance: float
    total_minimums: float
    projected_months: int
    payoff_order: List[Tuple[str, float]]


def calculate_snowball(debts: List[Debt], extra_payment: float = 0) -> SnowballSummary:
    if not debts:
        return SnowballSummary(0, 0, 0, [])

    sorted_debts = sorted(debts, key=lambda d: d.outstanding_amount)
    total_balance = sum(d.outstanding_amount for d in sorted_debts)
    total_minimums = sum(d.minimum_due for d in sorted_debts)

    months = 0
    payoff_order = []
    snowball_payment = extra_payment

    for debt in sorted_debts:
        payment = max(debt.minimum_due + snowball_payment, 1)
        months_for_debt = math.ceil(debt.outstanding_amount / payment)
        months += months_for_debt
        snowball_payment += debt.minimum_due
        payoff_order.append((debt.creditor, months_for_debt))

    return SnowballSummary(total_balance, total_minimums, months, payoff_order)


def setup_db():
    """Ensure database tables exist before handling requests."""
    with app.app_context():
        db.create_all()


# Initialize the schema immediately so CLI/WSGI entry points behave the same.
setup_db()


@app.route("/")
def dashboard():
    debts = Debt.query.order_by(Debt.outstanding_amount.asc()).all()
    snowball = calculate_snowball(debts, extra_payment=100)
    top_debt = debts[0] if debts else None

    return render_template(
        "dashboard.html",
        debts=debts,
        snowball=snowball,
        top_debt=top_debt,
    )


@app.route("/debts", methods=["POST"])
def add_debt():
    try:
        debt = Debt(
            debt_type=request.form["debt_type"],
            creditor=request.form["creditor"],
            outstanding_amount=float(request.form["outstanding_amount"]),
            interest_rate=float(request.form.get("interest_rate", 0) or 0),
            emi=float(request.form.get("emi", 0) or 0),
            minimum_due=float(request.form.get("minimum_due", 0) or 0),
        )
        db.session.add(debt)
        db.session.commit()
        flash("Debt added successfully", "success")
    except (KeyError, ValueError):
        flash("Unable to add debt. Please verify the form.", "error")

    return redirect(url_for("dashboard"))


@app.route("/debts/<int:debt_id>/delete", methods=["POST"])
def delete_debt(debt_id):
    debt = Debt.query.get_or_404(debt_id)
    db.session.delete(debt)
    db.session.commit()
    flash("Debt removed", "success")
    return redirect(url_for("dashboard"))


@app.route("/debts/payoff", methods=["POST"])
def payoff_top_debt():
    debt = Debt.query.order_by(Debt.outstanding_amount.asc()).first()
    if debt:
        db.session.delete(debt)
        db.session.commit()
        flash(f"Paid off {debt.creditor}", "success")
    else:
        flash("No debts to pay off", "info")

    return redirect(url_for("dashboard"))


@app.route("/debts/new")
def new_debt():
    return render_template("new_debt.html")


@app.route("/api/debts")
def api_debts():
    debts = Debt.query.order_by(Debt.outstanding_amount.asc()).all()
    snowball = calculate_snowball(debts, extra_payment=100)
    return jsonify(
        {
            "debts": [d.as_dict() for d in debts],
            "summary": {
                "total_balance": snowball.total_balance,
                "total_minimums": snowball.total_minimums,
                "projected_months": snowball.projected_months,
                "payoff_order": snowball.payoff_order,
            },
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
