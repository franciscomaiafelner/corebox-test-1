# Marketplace MVP — AI Context

Purpose: concise reference for the assistant to align on stack, scope, and delivery style.

## Corebox (WebApp Description)
CoreBox: a scalable two-sided marketplace for subscription boxes. The project rests on three fundamental pillars. First, a comprehensive portal that equips sellers with the core tools to manage their entire subscription business lifecycle on our platform. Second, a unified consumer marketplace designed for effortless discovery and centralized control over multiple subscriptions. The third and most critical pillar is the transactional backend, which must be engineered to reliably handle complex recurring payments between multiple parties, manage all user and order data, and ensure the integrity of the entire marketplace.

## Tech Stack (Simple First)
- HTML, CSS, JavaScript (vanilla) for UI.
- Python (Flask) for routing, pages, and APIs.
- SQLite (SQL) for storage in development.
- Jinja templates (bundled with Flask) for server-rendered pages.
- Auth: Flask-Login (sessions) + Werkzeug password hashing.
- Config: python-dotenv (optional) for `.env` variables.

Notes:
- Start with these only. Add Stripe and other services later when needed.
- Keep a monolith in one repo; no frontend build tools or heavy frameworks initially.

## Roadmap (Vertical Slices)
1) Slice 1 — Auth + Layout + Home
   - Register, login, logout (credentials).
   - Simple base layout and a home page with navigation.

2) Slice 2 — Product Page + Subscribe (stub)
   - Public product page with title, price, description.
   - "Subscribe" creates a subscription record; allow cancel toggle.

3) Slice 3 — Buyer Subscriptions
   - List current user subscriptions; cancel/reactivate.

4) Slice 4 — Seller Dashboard
   - Show active subscriptions count, simple MRR (sum of active price), recent subscriptions.

5) Slice 5 — Payments (later)
   - Integrate Stripe Checkout; webhook to mark subscription active on payment success.

6) Slice 6 — Deploy (later)
   - Deploy to a simple host; migrate SQLite to a managed DB.

## Data (Minimal to Start)
- users: id, email, password_hash, role ("buyer" | "seller").
- products: id, slug, title, price_cents, description.
- subscriptions: id, user_id, product_id, status ("active" | "canceled"), started_at, canceled_at.

## Delivery Preferences (Important)
- I am a beginner.
- Prefer the simplest possible solution with the least code possible.
- Use minimal dependencies and avoid unnecessary abstractions.
- Provide clear, comprehensible explanations of each change.
- Favor step-by-step guidance aligned with the slices above.

## Next Steps
- Implement Slice 1 scaffold (Flask app, SQLite schema, auth, home page).
- Seed one demo product (e.g., "Pro Plan" at $10/month) for testing.

