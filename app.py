import os
import sqlite3
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Display user portfolio"""

    user_id = session["user_id"]

    # Get user's cash balance
    rows = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash_balance = rows[0]["cash"]

    # Get user's stock holdings
    rows = db.execute(
        "SELECT symbol, SUM(shares) AS shares FROM history WHERE user_id = ? GROUP BY symbol", user_id)
    portfolio_items = []
    total_value = 0

    for row in rows:
        symbol = row["symbol"]
        shares = row["shares"]

        try:
            stock = lookup(symbol)
            price = stock["price"]
            total_value += shares * price
            portfolio_items.append({"symbol": symbol, "shares": shares,
                                   "price": price, "total": f"{shares * price:.2f}"})
        except:
            # Handle case where stock data is unavailable
            portfolio_items.append({"symbol": symbol, "shares": shares,
                                   "price": "N/A", "total": "N/A"})

    # Calculate total value
    total_value += cash_balance

    return render_template("index.html", portfolio_items=portfolio_items, cash_balance=f"{cash_balance:.2f}", total_value=f"{total_value:.2f}")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    else:
        # Ensure symbol was submitted
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)

        # Ensure shares was submitted
        shares = request.form.get("shares")
        if not shares:
            return apology("must provide shares", 400)

        try:
            shares = int(shares)
        except ValueError:
            return apology("shares must be a whole number", 400)

        if shares <= 0:
            return apology("number of shares must be positive", 400)

        # Lookup stock
        stock = lookup(symbol)
        if not stock:
            return apology("invalid stock symbol", 400)

        # Lookup user's cash
        user_id = session["user_id"]
        rows = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        user_cash = rows[0]["cash"]

        # Calculate cost
        cost = stock["price"] * shares

        # Ensure sufficient funds
        if cost > user_cash:
            return apology("insufficient funds", 400)

        # Update user's cash
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", cost, user_id)

        # Insert transaction into history
        db.execute("INSERT INTO history (user_id, symbol, shares, price) VALUES(?, ?, ?, ?)", user_id, symbol, shares, stock["price"])

        # Flash success message
        flash("Purchase successful!", "success")

        return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")

        # Validate symbol input
        if not symbol:
            return apology("must provide stock symbol", 400)
        if not symbol.isalpha():  # Check if symbol contains only letters
            return apology("symbol must contain only letters", 400)

        try:
            quote = lookup(symbol)
        except Exception as e:
            return apology(f"Error fetching quote: {e}", 500)

        if not quote:
            return apology("quote not found", 400)

        return render_template("quoted.html", stock=quote)


@app.route("/history")
@login_required
def history():
    """Show user's transaction history"""

    # Get user ID from session
    user_id = session["user_id"]

    # Get all transactions for the user
    rows = db.execute("SELECT symbol, shares, price, timestamp FROM history WHERE user_id = ?", user_id)
    transactions = []

    for row in rows:
        transaction = {
            "symbol": row["symbol"],
            "shares": row["shares"],
            "price": f"${row['price']:.2f}",
            "timestamp": row["timestamp"]
        }
        transactions.append(transaction)

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user."""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        password = request.form.get("password")
        if not password:
            return apology("must provide password", 400)

        # Ensure passwords match
        confirmation = request.form.get("confirmation")
        if password != confirmation:
            return apology("passwords do not match", 400)

        try:
            # Check if username already exists
            rows = db.execute("SELECT * FROM users WHERE username = ?", username)
            if len(rows) > 0:
                return apology("username already exists", 400)

            # Insert user into database
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))
        except ValueError:
            return apology("an error occurred while registering", 500)

        # Remember that user's ID
        user_id = db.execute("SELECT id FROM users WHERE username = ?", username)[0]["id"]
        session["user_id"] = user_id

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Get user ID from session
    user_id = session["user_id"]

    # Get user's stock holdings (symbols only)
    rows = db.execute("SELECT symbol FROM history WHERE user_id = ? GROUP BY symbol", user_id)
    portfolio_symbols = [row["symbol"] for row in rows]

    if request.method == "GET":
        return render_template("sell.html", portfolio_symbols=portfolio_symbols)

    else:
        # Ensure symbol was selected
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must select a stock", 400)

        # Ensure shares was submitted
        shares = request.form.get("shares")
        if not shares:
            return apology("must provide shares", 400)

        try:
            shares = int(shares)
        except ValueError:
            return apology("shares must be a whole number", 400)

        if shares <= 0:
            return apology("number of shares must be positive", 400)

        # Check if user owns enough shares
        rows = db.execute(
            "SELECT SUM(shares) AS shares FROM history WHERE user_id = ? AND symbol = ?", user_id, symbol)
        user_shares = rows[0]["shares"]
        if user_shares < shares:
            return apology(f"you don't own that many shares of {symbol}", 400)

        # Lookup current price
        stock = lookup(symbol)
        if not stock:
            return apology("invalid stock symbol", 400)

        # Calculate proceeds
        proceeds = shares * stock["price"]

        # Update user's cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", proceeds, user_id)

        # Insert transaction into history (negative shares to indicate sale)
        db.execute("INSERT INTO history (user_id, symbol, shares, price) VALUES(?, ?, ?, ?)", user_id, symbol, -shares, stock["price"])

        # Flash success message
        flash(f"Sold {shares} shares of {symbol}", "success")

        return redirect("/")



# Change password route
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user's password."""

    if request.method == "GET":
        return render_template("change_password.html")

    else:
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Validate input
        if not current_password:
            return apology("must provide current password", 400)
        if not new_password:
            return apology("must provide new password", 400)
        if not confirmation:
            return apology("must provide confirmation", 400)

        # Check if new passwords match
        if new_password != confirmation:
            return apology("passwords do not match", 400)

        # Get user ID
        user_id = session["user_id"]

        # Get user's current hash
        rows = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        if len(rows) != 1:
            return apology("user not found", 404)

        # Verify current password
        if not check_password_hash(rows[0]["hash"], current_password):
            return apology("incorrect current password", 403)

        # Hash the new password
        new_hash = generate_password_hash(new_password)

        # Update user's password hash
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user_id)

        # Flash success message
        flash("Password changed successfully!", "success")

        return redirect("/")
