import os
import sqlite3
from pathlib import Path

from flask import (
    Flask,
    g,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    abort,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import stripe


load_dotenv()


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    # Config
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-insecure-secret-change-me")

    # Ensure instance dir exists
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    # Database path
    db_path = os.environ.get("DATABASE") or str(Path(app.instance_path) / "app.db")
    app.config["DATABASE"] = db_path

    # Login manager
    login_manager = LoginManager(app)
    login_manager.login_view = "login"

    # Stripe config
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

    # ----- DB helpers -----
    def get_db():
        if "db" not in g:
            conn = sqlite3.connect(app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def close_db(_):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'buyer' CHECK (role IN ('buyer','seller')),
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slug TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                price_cents INTEGER NOT NULL,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('active','canceled')),
                started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                canceled_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            );
            """
        )

        # Lightweight migration: add seller_id and Stripe columns to products if missing
        cols = db.execute("PRAGMA table_info(products)").fetchall()
        col_names = {c[1] for c in cols}
        if "seller_id" not in col_names:
            db.execute("ALTER TABLE products ADD COLUMN seller_id INTEGER REFERENCES users(id)")
        if "stripe_price_id" not in col_names:
            db.execute("ALTER TABLE products ADD COLUMN stripe_price_id TEXT")

        # Users: add stripe_customer_id
        ucols = db.execute("PRAGMA table_info(users)").fetchall()
        ucol_names = {c[1] for c in ucols}
        if "stripe_customer_id" not in ucol_names:
            db.execute("ALTER TABLE users ADD COLUMN stripe_customer_id TEXT")

        # Subscriptions: add stripe_subscription_id
        scols = db.execute("PRAGMA table_info(subscriptions)").fetchall()
        scol_names = {c[1] for c in scols}
        if "stripe_subscription_id" not in scol_names:
            db.execute("ALTER TABLE subscriptions ADD COLUMN stripe_subscription_id TEXT")

        # Seed one demo product (idempotent)
        db.execute(
            """
            INSERT OR IGNORE INTO products (slug, title, price_cents, description)
            VALUES (?, ?, ?, ?)
            """,
            ("pro-plan", "Pro Plan", 1000, "Monthly plan for testing"),
        )
        db.commit()

    # Expose helpers on app for simple usage/testing
    app.get_db = get_db  # type: ignore[attr-defined]
    app.init_db = init_db  # type: ignore[attr-defined]

    # ----- Template filters -----
    @app.template_filter("usd")
    def usd(cents: int | float | None) -> str:
        try:
            value = (cents or 0) / 100
        except Exception:
            value = 0
        return f"${value:,.2f}"

    # ----- User model / loader -----
    class User(UserMixin):
        def __init__(self, id: int, email: str, password_hash: str, role: str):
            self.id = id
            self.email = email
            self.password_hash = password_hash
            self.role = role

    def user_from_row(row: sqlite3.Row | None) -> User | None:
        if row is None:
            return None
        return User(id=row["id"], email=row["email"], password_hash=row["password_hash"], role=row["role"])

    @login_manager.user_loader
    def load_user(user_id: str):
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return user_from_row(row)

    # ----- Routes -----
    @app.route("/")
    def home():
        db = get_db()
        products = db.execute(
            """
            SELECT p.*, u.email AS seller_email
            FROM products p
            LEFT JOIN users u ON u.id = p.seller_id
            ORDER BY p.id DESC
            """
        ).fetchall()
        return render_template("home.html", products=products)

    @app.route("/dashboard")
    @login_required
    def seller_dashboard():
        if getattr(current_user, "role", "buyer") != "seller":
            abort(403)
        db = get_db()
        active_count = db.execute(
            """
            SELECT COUNT(*) AS c
            FROM subscriptions s
            JOIN products p ON p.id = s.product_id
            WHERE s.status='active' AND p.seller_id = ?
            """,
            (current_user.id,),
        ).fetchone()[0]
        mrr_row = db.execute(
            """
            SELECT COALESCE(SUM(p.price_cents), 0) AS mrr
            FROM subscriptions s
            JOIN products p ON p.id = s.product_id
            WHERE s.status = 'active' AND p.seller_id = ?
            """,
            (current_user.id,),
        ).fetchone()
        mrr_cents = mrr_row["mrr"] if mrr_row and mrr_row["mrr"] is not None else 0

        recent = db.execute(
            """
            SELECT s.*, p.title, p.slug, p.price_cents, u.email
            FROM subscriptions s
            JOIN products p ON p.id = s.product_id
            JOIN users u ON u.id = s.user_id
            WHERE p.seller_id = ?
            ORDER BY s.started_at DESC
            LIMIT 10
            """,
            (current_user.id,),
        ).fetchall()

        return render_template(
            "dashboard.html",
            active_count=active_count,
            mrr_cents=mrr_cents,
            recent=recent,
        )

    @app.route("/subscriptions")
    @login_required
    def my_subscriptions():
        db = get_db()
        subs = db.execute(
            """
            SELECT s.*, p.title, p.slug, p.price_cents
            FROM subscriptions s
            JOIN products p ON p.id = s.product_id
            WHERE s.user_id = ?
            ORDER BY s.started_at DESC
            """,
            (current_user.id,),
        ).fetchall()
        return render_template("subscriptions.html", subs=subs)

    @app.route("/products/<slug>")
    def product_page(slug: str):
        db = get_db()
        product = db.execute("SELECT * FROM products WHERE slug = ?", (slug,)).fetchone()
        if product is None:
            abort(404)
        sub = None
        if current_user.is_authenticated:
            sub = db.execute(
                "SELECT * FROM subscriptions WHERE user_id = ? AND product_id = ? ORDER BY id DESC LIMIT 1",
                (current_user.id, product["id"]),
            ).fetchone()
        return render_template("product.html", product=product, sub=sub)

    # ----- Stripe Checkout -----
    @app.route("/checkout/<slug>", methods=["POST", "GET"])  # allow GET for simplicity
    @login_required
    def checkout(slug: str):
        db = get_db()
        product = db.execute("SELECT * FROM products WHERE slug = ?", (slug,)).fetchone()
        if product is None:
            abort(404)
        price_id = product["stripe_price_id"] if "stripe_price_id" in product.keys() else None
        if not price_id:
            flash("This product is not Stripe-enabled.", "error")
            return redirect(url_for("product_page", slug=slug))

        # Ensure we have a Stripe customer or use email to create one at checkout
        user_row = db.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()
        customer_id = (user_row["stripe_customer_id"] if user_row and "stripe_customer_id" in user_row.keys() else None)

        try:
            success_url = url_for("my_subscriptions", _external=True) + "?session_id={CHECKOUT_SESSION_ID}"
            cancel_url = url_for("product_page", slug=slug, _external=True)
            session = stripe.checkout.Session.create(
                mode="subscription",
                line_items=[{"price": price_id, "quantity": 1}],
                allow_promotion_codes=True,
                success_url=success_url,
                cancel_url=cancel_url,
                client_reference_id=str(current_user.id),
                customer=customer_id or None,
                customer_email=None if customer_id else current_user.email,
                metadata={
                    "user_id": str(current_user.id),
                    "product_id": str(product["id"]),
                    "price_id": price_id,
                    "slug": slug,
                },
            )
        except Exception as e:
            flash(f"Stripe error: {e}", "error")
            return redirect(url_for("product_page", slug=slug))

        return redirect(session.url, code=303)

    # ----- Stripe Billing Portal -----
    @app.route("/billing-portal")
    @login_required
    def billing_portal():
        db = get_db()
        row = db.execute("SELECT stripe_customer_id FROM users WHERE id = ?", (current_user.id,)).fetchone()
        customer_id = row["stripe_customer_id"] if row else None
        if not customer_id:
            flash("No Stripe customer found. Complete checkout first.", "error")
            return redirect(url_for("my_subscriptions"))
        try:
            portal = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=url_for("my_subscriptions", _external=True),
            )
        except Exception as e:
            flash(f"Stripe error: {e}", "error")
            return redirect(url_for("my_subscriptions"))
        return redirect(portal.url, code=303)

    # ----- Stripe Webhook -----
    @app.route("/webhook", methods=["POST"])
    def webhook():
        payload = request.data
        sig = request.headers.get("Stripe-Signature", "")
        try:
            event = stripe.Webhook.construct_event(payload, sig, webhook_secret)
        except Exception:
            return ("", 400)

        db = get_db()
        etype = event.get("type")
        data = event.get("data", {}).get("object", {})

        def upsert_sub(user_id: int, product_id: int, stripe_sub_id: str | None, active: bool):
            row = db.execute(
                "SELECT id, status FROM subscriptions WHERE user_id = ? AND product_id = ? ORDER BY id DESC LIMIT 1",
                (user_id, product_id),
            ).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO subscriptions (user_id, product_id, status, stripe_subscription_id) VALUES (?, ?, ?, ?)",
                    (user_id, product_id, "active" if active else "canceled", stripe_sub_id),
                )
            else:
                if active:
                    db.execute(
                        "UPDATE subscriptions SET status='active', started_at=CURRENT_TIMESTAMP, canceled_at=NULL, stripe_subscription_id=? WHERE id=?",
                        (stripe_sub_id, row["id"]),
                    )
                else:
                    db.execute(
                        "UPDATE subscriptions SET status='canceled', canceled_at=CURRENT_TIMESTAMP, stripe_subscription_id=? WHERE id=?",
                        (stripe_sub_id, row["id"]),
                    )
            db.commit()

        if etype == "checkout.session.completed":
            user_id = data.get("metadata", {}).get("user_id") or data.get("client_reference_id")
            product_id = data.get("metadata", {}).get("product_id")
            customer_id = data.get("customer")
            sub_id = data.get("subscription")
            # Attach customer to user record
            if user_id and customer_id:
                db.execute("UPDATE users SET stripe_customer_id = ? WHERE id = ?", (customer_id, int(user_id)))
                db.commit()
            if user_id and product_id:
                upsert_sub(int(user_id), int(product_id), sub_id, True)

        elif etype in ("customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"):
            sub = data
            status = sub.get("status")
            active = status in {"active", "trialing"}
            sub_id = sub.get("id")
            customer_id = sub.get("customer")
            # Find user by customer
            urow = db.execute("SELECT id FROM users WHERE stripe_customer_id = ?", (customer_id,)).fetchone()
            # Determine product via price on first item
            items = (sub.get("items", {}) or {}).get("data", [])
            price_id = items[0].get("price", {}).get("id") if items else None
            prow = db.execute("SELECT id FROM products WHERE stripe_price_id = ?", (price_id,)).fetchone() if price_id else None
            if urow and prow:
                upsert_sub(int(urow["id"]), int(prow["id"]), sub_id, active)

        return ("", 200)

    @app.route("/products/new", methods=["GET", "POST"])
    @login_required
    def new_product():
        if getattr(current_user, "role", "buyer") != "seller":
            abort(403)
        if request.method == "POST":
            slug = (request.form.get("slug") or "").strip().lower()
            title = (request.form.get("title") or "").strip()
            description = (request.form.get("description") or "").strip()
            price_str = (request.form.get("price_cents") or "").strip()
            stripe_price_id = (request.form.get("stripe_price_id") or "").strip() or None
            error = None
            try:
                price_cents = int(price_str)
            except Exception:
                price_cents = -1
            if not slug:
                error = "Slug is required."
            elif not title:
                error = "Title is required."
            elif price_cents < 0:
                error = "Price (cents) must be a non-negative integer."

            db = get_db()
            if error is None:
                exists = db.execute("SELECT 1 FROM products WHERE slug = ?", (slug,)).fetchone()
                if exists:
                    error = "Slug already exists. Choose another."

            if error is None:
                db.execute(
                    "INSERT INTO products (slug, title, price_cents, description, seller_id, stripe_price_id) VALUES (?, ?, ?, ?, ?, ?)",
                    (slug, title, price_cents, description, current_user.id, stripe_price_id),
                )
                db.commit()
                flash("Product created.", "success")
                return redirect(url_for("product_page", slug=slug))

            flash(error, "error")

        return render_template("new_product.html")

    @app.route("/products/<slug>/subscribe", methods=["POST"])
    @login_required
    def product_subscribe(slug: str):
        db = get_db()
        product = db.execute("SELECT * FROM products WHERE slug = ?", (slug,)).fetchone()
        if product is None:
            abort(404)
        # If Stripe is configured for this product, use Checkout flow instead
        if ("stripe_price_id" in product.keys()) and product["stripe_price_id"]:
            return redirect(url_for("checkout", slug=slug))
        sub = db.execute(
            "SELECT * FROM subscriptions WHERE user_id = ? AND product_id = ? ORDER BY id DESC LIMIT 1",
            (current_user.id, product["id"]),
        ).fetchone()

        if sub is None:
            db.execute(
                "INSERT INTO subscriptions (user_id, product_id, status) VALUES (?, ?, 'active')",
                (current_user.id, product["id"]),
            )
            db.commit()
            flash(f"Subscribed to {product['title']}.", "success")
        else:
            if sub["status"] == "active":
                db.execute(
                    "UPDATE subscriptions SET status='canceled', canceled_at=CURRENT_TIMESTAMP WHERE id = ?",
                    (sub["id"],),
                )
                db.commit()
                flash("Subscription canceled.", "success")
            else:
                db.execute(
                    "UPDATE subscriptions SET status='active', started_at=CURRENT_TIMESTAMP, canceled_at=NULL WHERE id = ?",
                    (sub["id"],),
                )
                db.commit()
                flash("Subscription reactivated.", "success")

        return redirect(url_for("product_page", slug=slug))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            role = (request.form.get("role") or "buyer").strip().lower()

            error = None
            if not email:
                error = "Email is required."
            elif not password:
                error = "Password is required."
            elif role not in {"buyer", "seller"}:
                error = "Role must be 'buyer' or 'seller'."

            db = get_db()
            if error is None:
                existing = db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
                if existing:
                    error = "An account with that email already exists."

            if error is None:
                pw_hash = generate_password_hash(password)
                cur = db.execute(
                    "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                    (email, pw_hash, role),
                )
                db.commit()
                # Auto-login after registration
                row = db.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
                user = user_from_row(row)
                if user:
                    login_user(user)
                    flash("Welcome! Your account was created.", "success")
                    return redirect(url_for("home"))
                else:
                    flash("Registration succeeded, but automatic login failed.", "warning")
                    return redirect(url_for("login"))

            flash(error, "error")

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""

            db = get_db()
            row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            user = user_from_row(row)

            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                flash("Logged in successfully.", "success")
                next_url = request.args.get("next")
                return redirect(next_url or url_for("home"))
            else:
                flash("Invalid email or password.", "error")

        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("You have been logged out.", "success")
        return redirect(url_for("home"))

    # Initialize DB on first run to reduce setup friction
    with app.app_context():
        init_db()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
