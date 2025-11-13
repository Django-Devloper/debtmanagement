import math
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from typing import Callable, Dict, List, Tuple

import jwt
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    url_for,
    flash,
    jsonify,
    g,
)
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
app.config["JWT_SECRET_KEY"] = "snowball-api-secret"
app.config["JWT_EXPIRATION_MINUTES"] = 60 * 12  # 12 hours

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


def generate_access_token(user: "User") -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=app.config["JWT_EXPIRATION_MINUTES"])).timestamp()),
    }
    token = jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def _decode_access_token(token: str):
    return jwt.decode(
        token,
        app.config["JWT_SECRET_KEY"],
        algorithms=["HS256"],
        options={"require": ["sub", "exp", "iat"]},
    )


def jwt_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return _json_error("Missing or invalid Authorization header.", status=401)
        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return _json_error("Missing token.", status=401)
        try:
            payload = _decode_access_token(token)
        except jwt.ExpiredSignatureError:
            return _json_error("Token has expired.", status=401)
        except jwt.InvalidTokenError:
            return _json_error("Invalid token.", status=401)

        try:
            user_id = int(payload.get("sub"))
        except (TypeError, ValueError):
            return _json_error("Invalid token subject.", status=401)

        user = User.query.get(user_id)
        if not user or user.email != payload.get("email"):
            return _json_error("User not found.", status=401)

        g.api_user = user
        return view_func(*args, **kwargs)

    return wrapper


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
    goals = db.relationship(
        "SavingsGoal", back_populates="user", cascade="all, delete-orphan"
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
    paid_amount = db.Column(db.Float, nullable=False, default=0.0)

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
            "paid_amount": self.paid_amount,
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


class SavingsGoal(db.Model):
    __tablename__ = "savings_goals"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    target_amount = db.Column(db.Float, nullable=False)
    current_amount = db.Column(db.Float, nullable=False, default=0.0)
    target_date = db.Column(db.Date, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="goals")

    @property
    def remaining_amount(self) -> float:
        return max(self.target_amount - self.current_amount, 0.0)

    @property
    def months_remaining(self) -> int:
        if not self.target_date:
            return 0
        today = datetime.utcnow().date()
        if self.target_date <= today:
            return 0
        return months_between(today, self.target_date)

    @property
    def recommended_monthly(self) -> float:
        if self.months_remaining == 0:
            if self.remaining_amount == 0:
                return 0.0
            return self.remaining_amount
        return self.remaining_amount / self.months_remaining

    @property
    def progress_percent(self) -> float:
        if self.target_amount <= 0:
            return 0.0
        return min((self.current_amount / self.target_amount) * 100, 100.0)

    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "target_amount": self.target_amount,
            "current_amount": self.current_amount,
            "remaining_amount": self.remaining_amount,
            "target_date": self.target_date.isoformat() if self.target_date else None,
            "months_remaining": self.months_remaining,
            "recommended_monthly": self.recommended_monthly,
            "progress_percent": self.progress_percent,
        }


@dataclass
class PayoffSummary:
    total_balance: float
    total_minimums: float
    projected_months: int
    payoff_order: List[Tuple[str, float]]
    balance_timeline: List[Dict[str, float]]


def payoff_summary_payload(summary: PayoffSummary) -> dict:
    return {
        "total_balance": summary.total_balance,
        "total_minimums": summary.total_minimums,
        "projected_months": summary.projected_months,
        "payoff_order": [
            {"creditor": creditor, "months": months}
            for creditor, months in summary.payoff_order
        ],
        "balance_timeline": summary.balance_timeline,
    }


def _calculate_payoff(
    debts: List[Debt],
    *,
    sort_key: Callable[[Debt], object],
    reverse: bool = False,
    extra_payment: float = 0,
) -> PayoffSummary:
    if not debts:
        return PayoffSummary(0, 0, 0, [], [{"month": 0, "balance": 0.0}])

    ordered_debts = sorted(debts, key=sort_key, reverse=reverse)
    total_balance = sum(d.outstanding_amount for d in ordered_debts)
    total_minimums = sum(d.minimum_due for d in ordered_debts)

    months = 0
    payoff_order: List[Tuple[str, float]] = []
    snowball_payment = extra_payment
    remaining_balance = total_balance
    timeline: List[Dict[str, float]] = [
        {"month": 0, "balance": round(total_balance, 2)}
    ]

    for debt in ordered_debts:
        payment = max(debt.minimum_due + snowball_payment, 1)
        months_for_debt = math.ceil(debt.outstanding_amount / payment)
        months += months_for_debt
        snowball_payment += debt.minimum_due
        payoff_order.append((debt.creditor, months_for_debt))
        remaining_balance = max(remaining_balance - debt.outstanding_amount, 0.0)
        timeline.append(
            {"month": months, "balance": round(remaining_balance, 2)}
        )

    return PayoffSummary(total_balance, total_minimums, months, payoff_order, timeline)


def calculate_snowball(debts: List[Debt], extra_payment: float = 0) -> PayoffSummary:
    return _calculate_payoff(
        debts, sort_key=lambda d: d.outstanding_amount, extra_payment=extra_payment
    )


def calculate_avalanche(debts: List[Debt], extra_payment: float = 0) -> PayoffSummary:
    return _calculate_payoff(
        debts,
        sort_key=lambda d: (d.interest_rate, d.outstanding_amount),
        reverse=True,
        extra_payment=extra_payment,
    )


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


def ensure_debt_paid_column():
    """Add the paid_amount tracker for partial payoff workflows."""

    inspector = inspect(db.engine)
    if "debts" not in inspector.get_table_names():
        return

    column_names = {column["name"] for column in inspector.get_columns("debts")}
    if "paid_amount" in column_names:
        return

    with db.engine.begin() as connection:
        connection.execute(
            text("ALTER TABLE debts ADD COLUMN paid_amount FLOAT NOT NULL DEFAULT 0")
        )


def months_between(start: date, end: date) -> int:
    """Rough month delta between two dates."""

    return max((end.year - start.year) * 12 + (end.month - start.month), 0)


def setup_db():
    """Ensure database tables exist before handling requests."""
    with app.app_context():
        db.create_all()
        ensure_debt_user_column()
        ensure_debt_paid_column()


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
    goals = (
        SavingsGoal.query.filter_by(user_id=current_user.id)
        .order_by(SavingsGoal.target_date.is_(None), SavingsGoal.target_date.asc())
        .all()
    )
    snowball = calculate_snowball(
        debts, extra_payment=current_user.monthly_extra_payment
    )
    avalanche = calculate_avalanche(
        debts, extra_payment=current_user.monthly_extra_payment
    )
    top_debt = debts[0] if debts else None
    total_income = sum(income.monthly_amount for income in incomes)
    net_after_minimums = total_income - snowball.total_minimums
    debt_count = len(debts)
    payoff_steps = len(snowball.payoff_order)
    progress = 0.0
    if snowball.projected_months > 0 and debt_count > 0:
        progress = (payoff_steps / debt_count) * 100

    snowball_sequence = [creditor for creditor, _ in snowball.payoff_order]
    avalanche_sequence = [creditor for creditor, _ in avalanche.payoff_order]
    emergency_target = round(snowball.total_minimums * 3, 2)
    goal_savings_total = sum(goal.current_amount for goal in goals)
    emergency_gap = max(emergency_target - goal_savings_total, 0)
    debt_progress = [
        {
            "id": debt.id,
            "label": debt.creditor,
            "paid": round(debt.paid_amount, 2),
            "remaining": round(max(debt.outstanding_amount, 0.0), 2),
        }
        for debt in debts
    ]
    chart_bootstrap = {
        "timeline": {
            "snowball": snowball.balance_timeline,
            "avalanche": avalanche.balance_timeline,
        },
        "months": {
            "snowball": snowball.projected_months,
            "avalanche": avalanche.projected_months,
        },
        "debtProgress": debt_progress,
    }

    return render_template(
        "dashboard.html",
        debts=debts,
        snowball=snowball,
        avalanche=avalanche,
        snowball_sequence=snowball_sequence,
        avalanche_sequence=avalanche_sequence,
        top_debt=top_debt,
        incomes=incomes,
        total_income=total_income,
        net_after_minimums=net_after_minimums,
        progress=progress,
        goals=goals,
        emergency_target=emergency_target,
        emergency_gap=emergency_gap,
        goal_savings_total=goal_savings_total,
        chart_bootstrap=chart_bootstrap,
    )


@app.route("/debts", methods=["POST"])
@login_required
def add_debt():
    try:
        outstanding = float(request.form["outstanding_amount"])
        rate = float(request.form.get("interest_rate", 0) or 0)
        emi = float(request.form.get("emi", 0) or 0)
        minimum = float(request.form.get("minimum_due", 0) or 0)
        if outstanding <= 0:
            raise ValueError
        if rate < 0 or emi < 0 or minimum < 0:
            raise ValueError
        debt = Debt(
            debt_type=request.form["debt_type"],
            creditor=request.form["creditor"],
            outstanding_amount=outstanding,
            interest_rate=rate,
            emi=emi,
            minimum_due=minimum,
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


@app.route("/debts/<int:debt_id>/payment", methods=["POST"])
@login_required
def pay_down_debt(debt_id):
    debt = Debt.query.filter_by(id=debt_id, user_id=current_user.id).first_or_404()
    if debt.outstanding_amount <= 0:
        flash("This debt is already paid off.", "info")
        return redirect(url_for("dashboard"))

    try:
        amount = request.form.get("amount", "0")
        applied = _apply_partial_payment(debt, amount)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("dashboard"))

    db.session.commit()
    flash(
        f"Applied ₹{applied:,.2f} toward {debt.creditor}. Remaining ₹{debt.outstanding_amount:,.2f}",
        "success",
    )
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
        if debt.outstanding_amount <= 0:
            flash(f"{debt.creditor} is already cleared.", "info")
        else:
            applied = _apply_partial_payment(debt, debt.outstanding_amount)
            db.session.commit()
            flash(
                f"Paid off {debt.creditor} with a ₹{applied:,.2f} payment.",
                "success",
            )
    else:
        flash("No debts to pay off", "info")

    return redirect(url_for("dashboard"))


@app.route("/debts/new")
@login_required
def new_debt():
    return render_template("new_debt.html")


@app.route("/api/v1/auth/token", methods=["POST"])
def api_v1_auth_token():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return _json_error("Email and password are required.")

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return _json_error("Invalid credentials.", status=401)

    token = generate_access_token(user)
    return jsonify(
        {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": app.config["JWT_EXPIRATION_MINUTES"] * 60,
        }
    )


@app.route("/api/debts")
@jwt_required
def api_debts():
    return jsonify(build_financial_snapshot(g.api_user))


@app.route("/api/v1/summary")
@jwt_required
def api_v1_summary():
    return jsonify(build_financial_snapshot(g.api_user))


@app.route("/api/v1/strategies")
@jwt_required
def api_v1_strategies():
    user = g.api_user
    debts = Debt.query.filter_by(user_id=user.id).all()
    snowball = calculate_snowball(debts, extra_payment=user.monthly_extra_payment)
    avalanche = calculate_avalanche(debts, extra_payment=user.monthly_extra_payment)
    return jsonify(
        {
            "strategies": {
                "snowball": payoff_summary_payload(snowball),
                "avalanche": payoff_summary_payload(avalanche),
            },
            "api_version": 1,
        }
    )


@app.route("/api/v1/debts", methods=["GET", "POST"])
@jwt_required
def api_v1_debts():
    user = g.api_user
    if request.method == "GET":
        debts = (
            Debt.query.filter_by(user_id=user.id)
            .order_by(Debt.outstanding_amount.asc())
            .all()
        )
        return jsonify({"debts": [d.as_dict() for d in debts]})

    data = request.get_json(silent=True) or {}
    required = [
        "debt_type",
        "creditor",
        "outstanding_amount",
        "interest_rate",
        "emi",
        "minimum_due",
    ]
    missing = [
        field
        for field in required
        if field not in data or data.get(field) in (None, "")
    ]
    if missing:
        return _json_error(f"Missing fields: {', '.join(missing)}")

    try:
        outstanding = float(data.get("outstanding_amount", 0))
        rate = float(data.get("interest_rate", 0))
        emi = float(data.get("emi", 0))
        minimum = float(data.get("minimum_due", 0))
    except (TypeError, ValueError):
        return _json_error("Amounts must be numeric.")

    if outstanding <= 0:
        return _json_error("Outstanding amount must be greater than zero.")
    if rate < 0 or emi < 0 or minimum < 0:
        return _json_error("Rates and payments must be zero or positive.")

    debt = Debt(
        debt_type=data["debt_type"],
        creditor=data["creditor"],
        outstanding_amount=outstanding,
        interest_rate=rate,
        emi=emi,
        minimum_due=minimum,
        user_id=user.id,
    )
    db.session.add(debt)
    db.session.commit()
    return jsonify({"debt": debt.as_dict()}), 201


@app.route("/api/v1/debts/<int:debt_id>", methods=["DELETE"])
@jwt_required
def api_v1_delete_debt(debt_id):
    debt = Debt.query.filter_by(id=debt_id, user_id=g.api_user.id).first()
    if not debt:
        return _json_error("Debt not found.", status=404)
    db.session.delete(debt)
    db.session.commit()
    return jsonify({"status": "deleted"})


@app.route("/api/v1/debts/<int:debt_id>/payment", methods=["POST"])
@jwt_required
def api_v1_pay_debt(debt_id):
    debt = Debt.query.filter_by(id=debt_id, user_id=g.api_user.id).first()
    if not debt:
        return _json_error("Debt not found.", status=404)
    if debt.outstanding_amount <= 0:
        return _json_error("Debt already paid off.")

    data = request.get_json(silent=True) or {}
    if "amount" not in data:
        return _json_error("amount is required.")

    try:
        applied = _apply_partial_payment(debt, data.get("amount"))
    except ValueError as exc:
        return _json_error(str(exc))

    db.session.commit()
    return jsonify({"debt": debt.as_dict(), "applied_amount": applied})


@app.route("/api/v1/incomes", methods=["GET", "POST"])
@jwt_required
def api_v1_incomes():
    user = g.api_user
    if request.method == "GET":
        incomes = (
            Income.query.filter_by(user_id=user.id)
            .order_by(Income.created_at.desc())
            .all()
        )
        return jsonify({"incomes": [income.as_dict() for income in incomes]})

    data = request.get_json(silent=True) or {}
    source = (data.get("source") or "").strip()
    if not source:
        return _json_error("Income source is required.")
    frequency = _validated_frequency(data.get("frequency", "monthly"))
    try:
        amount = float(data.get("amount", 0))
    except (TypeError, ValueError):
        return _json_error("Income amount must be numeric.")
    if amount <= 0:
        return _json_error("Income amount must be greater than zero.")

    income = Income(
        source=source,
        amount=amount,
        frequency=frequency,
        user_id=user.id,
    )
    db.session.add(income)
    db.session.commit()
    return jsonify({"income": income.as_dict()}), 201


@app.route("/api/v1/incomes/<int:income_id>", methods=["DELETE"])
@jwt_required
def api_v1_delete_income(income_id):
    income = Income.query.filter_by(id=income_id, user_id=g.api_user.id).first()
    if not income:
        return _json_error("Income not found.", status=404)
    db.session.delete(income)
    db.session.commit()
    return jsonify({"status": "deleted"})


@app.route("/api/v1/goals", methods=["GET", "POST"])
@jwt_required
def api_v1_goals():
    user = g.api_user
    if request.method == "GET":
        goals = (
            SavingsGoal.query.filter_by(user_id=user.id)
            .order_by(SavingsGoal.created_at.desc())
            .all()
        )
        return jsonify({"goals": [goal.as_dict() for goal in goals]})

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return _json_error("Goal name is required.")
    try:
        target_amount = float(data.get("target_amount", 0))
        current_amount = float(data.get("current_amount", 0))
    except (TypeError, ValueError):
        return _json_error("Amounts must be numeric.")
    if target_amount <= 0:
        return _json_error("Target amount must be greater than zero.")
    current_amount = max(min(current_amount, target_amount), 0)
    goal = SavingsGoal(
        name=name,
        target_amount=target_amount,
        current_amount=current_amount,
        target_date=_parse_date(data.get("target_date")),
        user_id=user.id,
    )
    db.session.add(goal)
    db.session.commit()
    return jsonify({"goal": goal.as_dict()}), 201


@app.route("/api/v1/goals/<int:goal_id>", methods=["PATCH", "DELETE"])
@jwt_required
def api_v1_goal_detail(goal_id):
    goal = SavingsGoal.query.filter_by(id=goal_id, user_id=g.api_user.id).first()
    if not goal:
        return _json_error("Goal not found.", status=404)

    if request.method == "DELETE":
        db.session.delete(goal)
        db.session.commit()
        return jsonify({"status": "deleted"})

    data = request.get_json(silent=True) or {}
    updated = False
    if "name" in data and isinstance(data.get("name"), str):
        goal.name = data["name"].strip() or goal.name
        updated = True
    if "target_amount" in data:
        try:
            target_amount = float(data["target_amount"])
        except (TypeError, ValueError):
            return _json_error("target_amount must be numeric.")
        if target_amount <= 0:
            return _json_error("target_amount must be greater than zero.")
        goal.target_amount = target_amount
        updated = True
    if "current_amount" in data:
        try:
            current_amount = float(data["current_amount"])
        except (TypeError, ValueError):
            return _json_error("current_amount must be numeric.")
        goal.current_amount = max(min(current_amount, goal.target_amount), 0)
        updated = True
    if "target_date" in data:
        parsed = _parse_date(data.get("target_date"))
        goal.target_date = parsed
        updated = True

    if updated:
        db.session.commit()
    return jsonify({"goal": goal.as_dict()})


def _validated_frequency(value: str) -> str:
    value = (value or "monthly").lower()
    return value if value in FREQUENCY_FACTORS else "monthly"


def _parse_date(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def _json_error(message: str, status: int = 400):
    return jsonify({"error": message}), status


def _apply_partial_payment(debt: Debt, amount: float) -> float:
    """Reduce the outstanding balance and return the applied amount."""

    try:
        payment = round(float(amount), 2)
    except (TypeError, ValueError):
        raise ValueError("Invalid payment amount")

    if payment <= 0:
        raise ValueError("Payment must be greater than zero")

    applied = min(payment, max(debt.outstanding_amount, 0.0))
    debt.outstanding_amount = round(max(debt.outstanding_amount - applied, 0.0), 2)
    debt.paid_amount = round((debt.paid_amount or 0.0) + applied, 2)
    if debt.outstanding_amount < 0.01:
        debt.outstanding_amount = 0.0
    return applied


def build_financial_snapshot(user: User) -> Dict[str, object]:
    debts = (
        Debt.query.filter_by(user_id=user.id)
        .order_by(Debt.outstanding_amount.asc())
        .all()
    )
    incomes = (
        Income.query.filter_by(user_id=user.id)
        .order_by(Income.created_at.desc())
        .all()
    )
    goals = (
        SavingsGoal.query.filter_by(user_id=user.id)
        .order_by(SavingsGoal.created_at.desc())
        .all()
    )
    snowball = calculate_snowball(debts, extra_payment=user.monthly_extra_payment)
    avalanche = calculate_avalanche(debts, extra_payment=user.monthly_extra_payment)
    total_income = sum(income.monthly_amount for income in incomes)
    net_after_minimums = total_income - snowball.total_minimums
    debt_count = len(debts)
    payoff_steps = len(snowball.payoff_order)
    progress = (payoff_steps / debt_count) * 100 if debt_count else 0.0
    goal_savings_total = sum(goal.current_amount for goal in goals)
    emergency_target = round(snowball.total_minimums * 3, 2)
    emergency_gap = max(emergency_target - goal_savings_total, 0)

    return {
        "api_version": 1,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "monthly_extra_payment": user.monthly_extra_payment,
        },
        "debts": [debt.as_dict() for debt in debts],
        "incomes": [income.as_dict() for income in incomes],
        "goals": [goal.as_dict() for goal in goals],
        "strategies": {
            "snowball": payoff_summary_payload(snowball),
            "avalanche": payoff_summary_payload(avalanche),
        },
        "cash_flow": {
            "total_income": total_income,
            "total_minimums": snowball.total_minimums,
            "net_after_minimums": net_after_minimums,
            "progress_percent": progress,
        },
        "insights": {
            "recommended_emergency_fund": emergency_target,
            "emergency_gap": emergency_gap,
            "goal_savings_total": goal_savings_total,
            "goal_count": len(goals),
        },
        "charts": {
            "timeline": {
                "snowball": snowball.balance_timeline,
                "avalanche": avalanche.balance_timeline,
            },
            "debt_progress": [
                {
                    "id": debt.id,
                    "label": debt.creditor,
                    "paid": round(debt.paid_amount, 2),
                    "remaining": round(max(debt.outstanding_amount, 0.0), 2),
                }
                for debt in debts
            ],
        },
    }


def build_openapi_spec() -> Dict[str, object]:
    server_url = request.host_url.rstrip("/")

    def schema_ref(name: str) -> Dict[str, str]:
        return {"$ref": f"#/components/schemas/{name}"}

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Snowball Finance API",
            "version": "1.0.0",
            "description": (
                "Authenticated JSON endpoints for building omni-channel"
                " debt, income, goal, and payoff experiences."
            ),
        },
        "servers": [{"url": server_url}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "Include `Authorization: Bearer <token>` on every request.",
                }
            },
            "schemas": {
                "TokenRequest": {
                    "type": "object",
                    "required": ["email", "password"],
                    "properties": {
                        "email": {"type": "string", "format": "email"},
                        "password": {"type": "string", "format": "password"},
                    },
                },
                "TokenResponse": {
                    "type": "object",
                    "properties": {
                        "access_token": {"type": "string"},
                        "token_type": {"type": "string", "example": "Bearer"},
                        "expires_in": {"type": "integer"},
                    },
                },
                "Debt": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "debt_type": {"type": "string"},
                        "creditor": {"type": "string"},
                        "outstanding_amount": {"type": "number", "format": "float"},
                        "interest_rate": {"type": "number", "format": "float"},
                        "emi": {"type": "number", "format": "float"},
                        "minimum_due": {"type": "number", "format": "float"},
                        "user_id": {"type": "integer"},
                        "paid_amount": {"type": "number", "format": "float"},
                    },
                },
                "DebtPayload": {
                    "type": "object",
                    "required": [
                        "debt_type",
                        "creditor",
                        "outstanding_amount",
                        "interest_rate",
                        "emi",
                        "minimum_due",
                    ],
                    "properties": {
                        "debt_type": {"type": "string"},
                        "creditor": {"type": "string"},
                        "outstanding_amount": {"type": "number", "format": "float"},
                        "interest_rate": {"type": "number", "format": "float"},
                        "emi": {"type": "number", "format": "float"},
                        "minimum_due": {"type": "number", "format": "float"},
                    },
                },
                "Income": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "source": {"type": "string"},
                        "amount": {"type": "number", "format": "float"},
                        "frequency": {"type": "string"},
                        "monthly_amount": {"type": "number", "format": "float"},
                    },
                },
                "IncomePayload": {
                    "type": "object",
                    "required": ["source", "amount"],
                    "properties": {
                        "source": {"type": "string"},
                        "amount": {"type": "number", "format": "float"},
                        "frequency": {
                            "type": "string",
                            "enum": list(FREQUENCY_FACTORS.keys()),
                            "default": "monthly",
                        },
                    },
                },
                "Goal": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"},
                        "target_amount": {"type": "number", "format": "float"},
                        "current_amount": {"type": "number", "format": "float"},
                        "remaining_amount": {"type": "number", "format": "float"},
                        "target_date": {"type": "string", "format": "date", "nullable": True},
                        "months_remaining": {"type": "integer"},
                        "recommended_monthly": {"type": "number", "format": "float"},
                        "progress_percent": {"type": "number", "format": "float"},
                    },
                },
                "GoalCreatePayload": {
                    "type": "object",
                    "required": ["name", "target_amount"],
                    "properties": {
                        "name": {"type": "string"},
                        "target_amount": {"type": "number", "format": "float"},
                        "current_amount": {
                            "type": "number",
                            "format": "float",
                            "default": 0,
                        },
                        "target_date": {"type": "string", "format": "date"},
                    },
                },
                "GoalUpdatePayload": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "target_amount": {"type": "number", "format": "float"},
                        "current_amount": {"type": "number", "format": "float"},
                        "target_date": {"type": "string", "format": "date"},
                    },
                },
                "TimelinePoint": {
                    "type": "object",
                    "properties": {
                        "month": {"type": "integer"},
                        "balance": {"type": "number", "format": "float"},
                    },
                },
                "StrategySummary": {
                    "type": "object",
                    "properties": {
                        "total_balance": {"type": "number", "format": "float"},
                        "total_minimums": {"type": "number", "format": "float"},
                        "projected_months": {"type": "integer"},
                        "payoff_order": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "creditor": {"type": "string"},
                                    "months": {"type": "number", "format": "float"},
                                },
                            },
                        },
                    },
                },
                "SummaryResponse": {
                    "type": "object",
                    "properties": {
                        "api_version": {"type": "integer"},
                        "generated_at": {"type": "string", "format": "date-time"},
                        "user": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "integer"},
                                "name": {"type": "string"},
                                "email": {"type": "string", "format": "email"},
                                "monthly_extra_payment": {"type": "number", "format": "float"},
                            },
                        },
                        "debts": {"type": "array", "items": schema_ref("Debt")},
                        "incomes": {"type": "array", "items": schema_ref("Income")},
                        "goals": {"type": "array", "items": schema_ref("Goal")},
                        "strategies": {
                            "type": "object",
                            "properties": {
                                "snowball": schema_ref("StrategySummary"),
                                "avalanche": schema_ref("StrategySummary"),
                            },
                        },
                        "cash_flow": {
                            "type": "object",
                            "properties": {
                                "total_income": {"type": "number", "format": "float"},
                                "total_minimums": {"type": "number", "format": "float"},
                                "net_after_minimums": {"type": "number", "format": "float"},
                                "progress_percent": {"type": "number", "format": "float"},
                            },
                        },
                        "insights": {
                            "type": "object",
                            "properties": {
                                "recommended_emergency_fund": {"type": "number", "format": "float"},
                                "emergency_gap": {"type": "number", "format": "float"},
                                "goal_savings_total": {"type": "number", "format": "float"},
                                "goal_count": {"type": "integer"},
                            },
                        },
                    },
                },
                "ErrorResponse": {
                    "type": "object",
                    "properties": {"error": {"type": "string"}},
                },
                "StatusResponse": {
                    "type": "object",
                    "properties": {"status": {"type": "string", "example": "deleted"}},
                },
            },
        },
        "paths": {
            "/api/v1/auth/token": {
                "post": {
                    "tags": ["Auth"],
                    "summary": "Exchange credentials for a JWT",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": schema_ref("TokenRequest")}
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "JWT issued",
                            "content": {
                                "application/json": {"schema": schema_ref("TokenResponse")}
                            },
                        },
                        "401": {
                            "description": "Invalid credentials",
                            "content": {
                                "application/json": {"schema": schema_ref("ErrorResponse")}
                            },
                        },
                    },
                }
            },
            "/api/v1/summary": {
                "get": {
                    "tags": ["Snapshots"],
                    "summary": "Fetch the holistic financial snapshot",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Snapshot payload",
                            "content": {
                                "application/json": {"schema": schema_ref("SummaryResponse")}
                            },
                        },
                        "401": {
                            "description": "Missing or invalid token",
                            "content": {
                                "application/json": {"schema": schema_ref("ErrorResponse")}
                            },
                        },
                    },
                }
            },
            "/api/v1/strategies": {
                "get": {
                    "tags": ["Snapshots"],
                    "summary": "Compare snowball vs avalanche payoff timelines",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Strategy comparison",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "strategies": {
                                                "type": "object",
                                                "properties": {
                                                    "snowball": schema_ref("StrategySummary"),
                                                    "avalanche": schema_ref("StrategySummary"),
                                                },
                                            },
                                            "api_version": {"type": "integer"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/api/v1/debts": {
                "get": {
                    "tags": ["Debts"],
                    "summary": "List debts for the authenticated user",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "User debts",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "debts": {
                                                "type": "array",
                                                "items": schema_ref("Debt"),
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
                "post": {
                    "tags": ["Debts"],
                    "summary": "Capture a new debt",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": schema_ref("DebtPayload")}
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "Debt stored",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"debt": schema_ref("Debt")},
                                    }
                                }
                            },
                        },
                        "400": {
                            "description": "Validation error",
                            "content": {
                                "application/json": {"schema": schema_ref("ErrorResponse")}
                            },
                        },
                    },
                },
            },
            "/api/v1/debts/{debt_id}": {
                "delete": {
                    "tags": ["Debts"],
                    "summary": "Delete a debt",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "debt_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Debt removed",
                            "content": {
                                "application/json": {"schema": schema_ref("StatusResponse")}
                            },
                        },
                        "404": {
                            "description": "Debt not found",
                            "content": {
                                "application/json": {"schema": schema_ref("ErrorResponse")}
                            },
                        },
                    },
                }
            },
            "/api/v1/debts/{debt_id}/payment": {
                "post": {
                    "tags": ["Debts"],
                    "summary": "Apply a partial payment",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "debt_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["amount"],
                                    "properties": {
                                        "amount": {
                                            "type": "number",
                                            "format": "float",
                                            "description": "Amount to apply toward the balance.",
                                        }
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Updated debt with new balances",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "applied_amount": {
                                                "type": "number",
                                                "format": "float",
                                            },
                                            "debt": schema_ref("Debt"),
                                        },
                                    }
                                }
                            },
                        },
                        "400": {
                            "description": "Validation error",
                            "content": {
                                "application/json": {"schema": schema_ref("ErrorResponse")}
                            },
                        },
                        "404": {
                            "description": "Debt not found",
                            "content": {
                                "application/json": {"schema": schema_ref("ErrorResponse")}
                            },
                        },
                    },
                }
            },
            "/api/v1/incomes": {
                "get": {
                    "tags": ["Income"],
                    "summary": "List incomes for the authenticated user",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Income streams",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "incomes": {
                                                "type": "array",
                                                "items": schema_ref("Income"),
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
                "post": {
                    "tags": ["Income"],
                    "summary": "Add a new income stream",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": schema_ref("IncomePayload")}
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "Income saved",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"income": schema_ref("Income")},
                                    }
                                }
                            },
                        },
                    },
                },
            },
            "/api/v1/incomes/{income_id}": {
                "delete": {
                    "tags": ["Income"],
                    "summary": "Delete an income stream",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "income_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Income removed",
                            "content": {
                                "application/json": {"schema": schema_ref("StatusResponse")}
                            },
                        },
                        "404": {
                            "description": "Income not found",
                            "content": {
                                "application/json": {"schema": schema_ref("ErrorResponse")}
                            },
                        },
                    },
                }
            },
            "/api/v1/goals": {
                "get": {
                    "tags": ["Goals"],
                    "summary": "List savings goals",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Goal list",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "goals": {
                                                "type": "array",
                                                "items": schema_ref("Goal"),
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
                "post": {
                    "tags": ["Goals"],
                    "summary": "Create a savings goal",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": schema_ref("GoalCreatePayload")}
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "Goal saved",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"goal": schema_ref("Goal")},
                                    }
                                }
                            },
                        },
                    },
                },
            },
            "/api/v1/goals/{goal_id}": {
                "patch": {
                    "tags": ["Goals"],
                    "summary": "Update a savings goal",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "goal_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "requestBody": {
                        "required": False,
                        "content": {
                            "application/json": {"schema": schema_ref("GoalUpdatePayload")}
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Goal updated",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"goal": schema_ref("Goal")},
                                    }
                                }
                            },
                        },
                        "404": {
                            "description": "Goal not found",
                            "content": {
                                "application/json": {"schema": schema_ref("ErrorResponse")}
                            },
                        },
                    },
                },
                "delete": {
                    "tags": ["Goals"],
                    "summary": "Delete a savings goal",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "goal_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Goal removed",
                            "content": {
                                "application/json": {"schema": schema_ref("StatusResponse")}
                            },
                        },
                        "404": {
                            "description": "Goal not found",
                            "content": {
                                "application/json": {"schema": schema_ref("ErrorResponse")}
                                    },
                                },
                            },
                        },
                        "balance_timeline": {
                            "type": "array",
                            "items": schema_ref("TimelinePoint"),
                        },
                    },
                },
    }


@app.route("/api/docs.json")
def api_docs_spec():
    return jsonify(build_openapi_spec())


@app.route("/api/docs")
def api_docs_page():
    return render_template("swagger.html", spec_url=url_for("api_docs_spec"))


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


@app.route("/goals", methods=["POST"])
@login_required
def add_goal():
    name = request.form.get("name", "").strip()
    target_raw = request.form.get("target_amount", "0").strip()
    current_raw = request.form.get("current_amount", "0").strip()
    date_raw = request.form.get("target_date", "").strip()

    if not name:
        flash("Goal name is required.", "error")
        return redirect(url_for("dashboard"))

    try:
        target_amount = float(target_raw)
        current_amount = float(current_raw or 0)
    except ValueError:
        flash("Amounts must be numeric.", "error")
        return redirect(url_for("dashboard"))

    if target_amount <= 0:
        flash("Target amount must be greater than zero.", "error")
        return redirect(url_for("dashboard"))

    current_amount = max(min(current_amount, target_amount), 0)

    goal = SavingsGoal(
        name=name,
        target_amount=target_amount,
        current_amount=current_amount,
        target_date=_parse_date(date_raw),
        user_id=current_user.id,
    )
    db.session.add(goal)
    db.session.commit()
    flash("Savings goal captured.", "success")
    return redirect(url_for("dashboard"))


@app.route("/goals/<int:goal_id>/delete", methods=["POST"])
@login_required
def delete_goal(goal_id):
    goal = SavingsGoal.query.filter_by(id=goal_id, user_id=current_user.id).first_or_404()
    db.session.delete(goal)
    db.session.commit()
    flash("Goal removed.", "success")
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
