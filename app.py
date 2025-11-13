import math
from dataclasses import dataclass
from datetime import datetime
from typing import List, Tuple

from flask import Flask, redirect, render_template, request, url_for, flash, jsonify
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///snowball.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "snowball-secret"

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


FREQUENCY_FACTORS = {
    "monthly": 1.0,
    "biweekly": 26 / 12,
    "weekly": 52 / 12,
    "daily": 30,
    "yearly": 1 / 12,
    "quarterly": 1 / 3,
}


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    monthly_extra_payment = db.Column(db.Float, nullable=False, default=100.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    debts = db.relationship("Debt", back_populates="user", cascade="all, delete-orphan")
    incomes = db.relationship(
        "Income", back_populates="user", cascade="all, delete-orphan"
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Debt(db.Model):
    __tablename__ = "debts"

    id = db.Column(db.Integer, primary_key=True)
    debt_type = db.Column(db.String(120), nullable=False)
    creditor = db.Column(db.String(120), nullable=False)
    outstanding_amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    emi = db.Column(db.Float, nullable=False)
    minimum_due = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="debts")

    def as_dict(self):
        return {
            "id": self.id,
            "debt_type": self.debt_type,
            "creditor": self.creditor,
            "outstanding_amount": self.outstanding_amount,
            "interest_rate": self.interest_rate,
            "emi": self.emi,
            "minimum_due": self.minimum_due,
            "user_id": self.user_id,
        }


class Income(db.Model):
    __tablename__ = "income_streams"

    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    frequency = db.Column(db.String(32), nullable=False, default="monthly")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="incomes")

    @property
    def monthly_amount(self) -> float:
        factor = FREQUENCY_FACTORS.get(self.frequency, 1.0)
        return self.amount * factor

    def as_dict(self):
        return {
            "id": self.id,
            "source": self.source,
            "amount": self.amount,
            "frequency": self.frequency,
            "monthly_amount": self.monthly_amount,
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


def ensure_debt_user_column():
    """Backfill the user_id column for legacy databases."""

    inspector = inspect(db.engine)
    if "debts" not in inspector.get_table_names():
        return

    column_names = {column["name"] for column in inspector.get_columns("debts")}
    if "user_id" in column_names:
        return

    with db.engine.begin() as connection:
        connection.execute(
            text("ALTER TABLE debts ADD COLUMN user_id INTEGER REFERENCES users(id)")
        )


def setup_db():
    """Ensure database tables exist before handling requests."""
    with app.app_context():
        db.create_all()
        ensure_debt_user_column()


# Initialize the schema immediately so CLI/WSGI entry points behave the same.
setup_db()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
@login_required
def dashboard():
    debts = (
        Debt.query.filter_by(user_id=current_user.id)
        .order_by(Debt.outstanding_amount.asc())
        .all()
    )
    incomes = (
        Income.query.filter_by(user_id=current_user.id)
        .order_by(Income.created_at.desc())
        .all()
    )
    snowball = calculate_snowball(debts, extra_payment=current_user.monthly_extra_payment)
    top_debt = debts[0] if debts else None
    total_income = sum(income.monthly_amount for income in incomes)
    net_after_minimums = total_income - snowball.total_minimums

    return render_template(
        "dashboard.html",
        debts=debts,
        snowball=snowball,
        top_debt=top_debt,
        incomes=incomes,
        total_income=total_income,
        net_after_minimums=net_after_minimums,
    )


@app.route("/debts", methods=["POST"])
@login_required
def add_debt():
    try:
        debt = Debt(
            debt_type=request.form["debt_type"],
            creditor=request.form["creditor"],
            outstanding_amount=float(request.form["outstanding_amount"]),
            interest_rate=float(request.form.get("interest_rate", 0) or 0),
            emi=float(request.form.get("emi", 0) or 0),
            minimum_due=float(request.form.get("minimum_due", 0) or 0),
            user_id=current_user.id,
        )
        db.session.add(debt)
        db.session.commit()
        flash("Debt added successfully", "success")
    except (KeyError, ValueError):
        flash("Unable to add debt. Please verify the form.", "error")

    return redirect(url_for("dashboard"))


@app.route("/debts/<int:debt_id>/delete", methods=["POST"])
@login_required
def delete_debt(debt_id):
    debt = Debt.query.filter_by(id=debt_id, user_id=current_user.id).first_or_404()
    db.session.delete(debt)
    db.session.commit()
    flash("Debt removed", "success")
    return redirect(url_for("dashboard"))


@app.route("/debts/payoff", methods=["POST"])
@login_required
def payoff_top_debt():
    debt = (
        Debt.query.filter_by(user_id=current_user.id)
        .order_by(Debt.outstanding_amount.asc())
        .first()
    )
    if debt:
        db.session.delete(debt)
        db.session.commit()
        flash(f"Paid off {debt.creditor}", "success")
    else:
        flash("No debts to pay off", "info")

    return redirect(url_for("dashboard"))


@app.route("/debts/new")
@login_required
def new_debt():
    return render_template("new_debt.html")


@app.route("/api/debts")
@login_required
def api_debts():
    debts = (
        Debt.query.filter_by(user_id=current_user.id)
        .order_by(Debt.outstanding_amount.asc())
        .all()
    )
    incomes = (
        Income.query.filter_by(user_id=current_user.id)
        .order_by(Income.created_at.desc())
        .all()
    )
    snowball = calculate_snowball(debts, extra_payment=current_user.monthly_extra_payment)
    return jsonify(
        {
            "debts": [d.as_dict() for d in debts],
            "summary": {
                "total_balance": snowball.total_balance,
                "total_minimums": snowball.total_minimums,
                "projected_months": snowball.projected_months,
                "payoff_order": snowball.payoff_order,
            },
            "user": {
                "name": current_user.name,
                "email": current_user.email,
                "monthly_extra_payment": current_user.monthly_extra_payment,
            },
            "incomes": [income.as_dict() for income in incomes],
            "total_income": sum(income.monthly_amount for income in incomes),
        }
    )


def _validated_frequency(value: str) -> str:
    value = (value or "monthly").lower()
    return value if value in FREQUENCY_FACTORS else "monthly"


@app.route("/incomes", methods=["POST"])
@login_required
def add_income():
    source = request.form.get("source", "").strip()
    amount_raw = request.form.get("amount", "0").strip()
    frequency = _validated_frequency(request.form.get("frequency", "monthly"))

    if not source:
        flash("Income source is required.", "error")
        return redirect(url_for("dashboard"))

    try:
        amount = float(amount_raw)
    except ValueError:
        flash("Income amount must be numeric.", "error")
        return redirect(url_for("dashboard"))

    if amount <= 0:
        flash("Income amount must be greater than zero.", "error")
        return redirect(url_for("dashboard"))

    income = Income(
        source=source,
        amount=amount,
        frequency=frequency,
        user_id=current_user.id,
    )
    db.session.add(income)
    db.session.commit()
    flash("Income stream saved.", "success")
    return redirect(url_for("dashboard"))


@app.route("/incomes/<int:income_id>/delete", methods=["POST"])
@login_required
def delete_income(income_id):
    income = Income.query.filter_by(id=income_id, user_id=current_user.id).first_or_404()
    db.session.delete(income)
    db.session.commit()
    flash("Income removed.", "success")
    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.", "error")
        elif User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
        else:
            user = User(name=name, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            assign_legacy_debts(user)
            login_user(user)
            flash("Welcome! Your account is ready.", "success")
            return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            assign_legacy_debts(user)
            login_user(user)
            flash("Logged in successfully.", "success")
            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        name = request.form.get("name", current_user.name).strip()
        email = request.form.get("email", current_user.email).strip().lower()
        extra_payment_raw = request.form.get(
            "monthly_extra_payment", current_user.monthly_extra_payment
        )

        if not name or not email:
            flash("Name and email cannot be empty.", "error")
        else:
            existing = User.query.filter(
                User.email == email, User.id != current_user.id
            ).first()
            if existing:
                flash("Email already in use.", "error")
            else:
                current_user.name = name
                current_user.email = email
                try:
                    current_user.monthly_extra_payment = float(extra_payment_raw or 0)
                except ValueError:
                    flash("Monthly extra payment must be numeric.", "error")
                else:
                    db.session.commit()
                    flash("Profile updated.", "success")
                    return redirect(url_for("profile"))

    return render_template("profile.html")


def assign_legacy_debts(user: User) -> None:
    """Attach debts created before authentication to the provided user."""

    legacy_debts = Debt.query.filter(Debt.user_id.is_(None)).all()
    if not legacy_debts:
        return

    for debt in legacy_debts:
        debt.user_id = user.id
    db.session.commit()


if __name__ == "__main__":
    app.run(debug=True)
