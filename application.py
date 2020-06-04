import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime
from helpers import apology, login_required, lookup, usd, check_password_requirement

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks_symbol = db.execute("SELECT symbol FROM buy_history WHERE user_id = :user_id ORDER BY symbol",
                               user_id=session["user_id"])
    stock_summary = {}
    stock_summary_2 = {}
    cash_left_row = db.execute("SELECT cash FROM users WHERE id = :user_id",
                               user_id=session["user_id"])
    for symbol in stocks_symbol:
        if symbol["symbol"] not in stock_summary_2.keys():
            stock_information = lookup(symbol["symbol"])
            stock_summary_2[symbol["symbol"]] = (stock_information["name"], stock_information["price"])
        if symbol["symbol"] not in stock_summary.keys():
            row = db.execute("SELECT SUM(count) FROM buy_history WHERE user_id=:user_id GROUP BY symbol HAVING symbol=:symbol",
                             user_id=session["user_id"], symbol=symbol["symbol"])
            stock_summary[symbol["symbol"]] = row[0]["SUM(count)"]
    total_value_of_stocks = 0
    for key, value in stock_summary.items():
        if key in stock_summary_2.keys():
            total_value_of_stocks += value * stock_summary_2[key][1]
    grand_total_portfolio_value = total_value_of_stocks + cash_left_row[0]["cash"]
    return render_template("index.html", stock_summary=stock_summary, stock_summary_2=stock_summary_2, cash_left=cash_left_row[0]["cash"], grand_total_portfolio_value=grand_total_portfolio_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        stock_symbol = request.form.get("symbol").upper()
        lookup_share = lookup(stock_symbol)
        if not stock_symbol or not lookup_share:
            return apology("must provide a valid stock ticker symbol", 403)
        else:
            if not request.form.get("shares"):
                return apology("must provide number of shares", 403)
            elif int(request.form.get("shares")) <= 0:
                return apology("must provide a positive integer greater than 0 for number of shares", 403)
            else:
                stock_shares = int(request.form.get("shares"))
                current_price_share = lookup_share["price"]
                rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
                current_cash_available = rows[0]["cash"]
                total_price = current_price_share * stock_shares
                if current_cash_available < total_price:
                    return apology("you have insufficient cash to perform transaction", 403)
                db.execute("INSERT INTO buy_history (user_id, symbol, count, transaction_price, dateTime) VALUES (:user_id, :symbol, :count, :transaction_price, :dateTime)",
                           user_id=session["user_id"], symbol=stock_symbol, count=stock_shares, transaction_price=current_price_share, dateTime=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                db.execute("UPDATE users SET cash = :cash_left WHERE id = :user_id",
                           cash_left=current_cash_available - total_price, user_id=session["user_id"])
                flash("Shares bought successfully!")
                return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history_dict = db.execute("SELECT symbol, count, transaction_price, dateTime FROM buy_history WHERE user_id = :user_id ORDER BY id DESC;",
                              user_id=session["user_id"])
    return render_template("history.html", history_dict=history_dict)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # creates the table that stores users stock data
        db.execute("CREATE TABLE IF NOT EXISTS buy_history (id INTEGER NOT NULL PRIMARY KEY, user_id INTEGER NOT NULL, symbol varchar(255) NOT NULL, count NUMERIC NOT NULL, transaction_price NUMERIC NOT NULL, dateTime DATETIME NOT NULL)")

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide stock ticker symbol", 403)
        else:
            quoted_stock = lookup(symbol)
            if not quoted_stock:
                return apology("must provide valid stock ticker symbol", 403)
            else:
                return render_template("quoted.html", quoted_stock=quoted_stock)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Checks if username exists in database
        else:
            # Query database for username
            rows = db.execute("SELECT * FROM users WHERE username = :username",
                              username=request.form.get("username"))
            if len(rows) != 0:
                return apology("username already exists. choose another username.", 403)

            # Ensure password was submitted
            if not request.form.get("password"):
                return apology("must provide password", 403)

            # Ensure both password match
            elif request.form.get("password") != request.form.get("confirmation"):
                return apology("the passwords do not match", 403)

            # creates new user. stores username and password hash in db if password meets requirement. after creating user, redirects the user to login
            else:
                password = request.form.get("password")

                if check_password_requirement(password):
                    db.execute("INSERT INTO users (username, hash) VALUES (:username, :password_hash)",
                               username=request.form.get("username"), password_hash=generate_password_hash(password))
                    return redirect("/login")
                else:
                    return apology("password does not meet requirement", 403)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        stocks_symbol = db.execute("SELECT symbol FROM buy_history WHERE user_id = :user_id ORDER BY symbol",
                                   user_id=session["user_id"])
        dict_stock_details = {}
        for symbol in stocks_symbol:
            if symbol["symbol"] not in dict_stock_details.keys():
                row = db.execute("SELECT SUM(count) FROM buy_history WHERE user_id=:user_id GROUP BY symbol HAVING symbol=:symbol",
                                 user_id=session["user_id"], symbol=symbol["symbol"])
                dict_stock_details[symbol["symbol"]] = row[0]["SUM(count)"]
        print(dict_stock_details)
        return render_template("sell.html", dict_stock_details=dict_stock_details)
    else:
        if not request.form.get("symbol"):
            return apology("please select a valid stock ticker symbol that you own", 403)
        else:
            if not request.form.get("shares"):
                return apology("must provide number of shares", 403)
            elif int(request.form.get("shares")) <= 0:
                return apology("must provide a positive integer greater than 0 for number of shares", 403)
            else:
                symbol = request.form.get("symbol")
                shares = int(request.form.get("shares"))
                row = db.execute("SELECT SUM(count) FROM buy_history WHERE user_id=:user_id GROUP BY symbol HAVING symbol=:symbol",
                                 user_id=session["user_id"], symbol=symbol)
                if shares > row[0]["SUM(count)"]:
                    apology_string = "you do not own that many " + symbol + " shares"
                    return apology(apology_string, 403)
                else:
                    lookup_share = lookup(symbol)
                    current_share_price = lookup_share["price"]
                    total_gain = shares * current_share_price
                    rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
                    current_cash_available = rows[0]["cash"]
                    db.execute("INSERT INTO buy_history (user_id, symbol, count, transaction_price, dateTime) VALUES (:user_id, :symbol, :count, :transaction_price, :dateTime)",
                               user_id=session["user_id"], symbol=symbol, count=shares * -1, transaction_price=current_share_price, dateTime=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

                    db.execute("UPDATE users SET cash = :cash_left WHERE id = :user_id",
                               cash_left=current_cash_available + total_gain, user_id=session["user_id"])
                    flash("Shares sold successfully!")
                    return redirect("/")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("change_password.html")
    else:
        new_password = request.form.get("password")
        new_confirmation = request.form.get("confirmation")
        if not new_password or not new_confirmation:
            return apology("you left one or more inputs blank", 403)
        elif new_password != new_confirmation:
            return apology("the new passwords do not match", 403)
        elif check_password_requirement(new_password):
            db.execute("UPDATE users SET hash = :password_hash WHERE id = :user_id",
                       password_hash=generate_password_hash(new_password), user_id=session["user_id"])
            flash("Password changed successfully!")
            return redirect("/")
        else:
            return apology("password does not meet requirement", 403)


@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():
    if request.method == "GET":
        return render_template("cash.html")
    else:
        cash_amount = int(request.form.get("cash"))
        if not cash_amount:
            return apology("you left the input blank", 403)
        else:
            rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
            current_cash_available = rows[0]["cash"]
            total_cash = current_cash_available + cash_amount
            if total_cash < 0:
                total_cash = 0
            db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", cash=total_cash, user_id=session["user_id"])
            flash("Updated cash!")
            return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
