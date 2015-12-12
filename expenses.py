#!/usr/bin/python3

import logging
import sqlite3
from contextlib import closing
from flask import Flask, request, session, g, redirect, url_for, \
             abort, render_template, flash
import hashlib, uuid
from flask_bootstrap import Bootstrap
import time
from datetime import datetime, timedelta
import calendar
import pytz
from simpleeval import simple_eval

app = Flask(__name__)
Bootstrap(app)

app.config.from_object("config")

local_tz = pytz.timezone(app.config['TIMEZONE'])

def get_db():
    """
    Singleton for retrieving database connection object
    Returns sqlite3 db obj
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])

    return db

def get_all_users():
    """
    Get all usernames in database
    Returns list of usernames
    """
    query = """
    SELECT username
    FROM Users
    WHERE username != ?
    """
    db = get_db()
    cur = db.cursor()
    cur.execute(query, (session["username"],))
    users = [row[0] for row in cur.fetchall()]

    return users

def get_username(user_id):
    """
    Get username for user id
    Returns username string
    """
    query = """
    SELECT username
    FROM Users
    WHERE id = ?
    """

    db = get_db()
    cur = db.cursor()
    cur.execute(query, (user_id,))
    result = cur.fetchone()
    if result:
        return result[0]

    return "Unknown"

def get_user_pair_id(user1, user2, last_try=False):
    """
    Gets a user pair id for user1 and user2
    Only one pair id exists for a combo of users
    Returns int id of pair
    """
    query = """
    SELECT up.id
    FROM UserPair up
    JOIN Users u1
        ON up.user1 = u1.id
    JOIN Users u2
        ON up.user2 = u2.id
    WHERE u1.username = ?
    AND u2.username = ?
    """

    db = get_db()
    cur = db.cursor()
    cur.execute(query, (user1, user2))
    result = cur.fetchone()
    if result:
        return result[0]

    # two possible combos for pair id:
    # user1, user2
    # user2, user1
    # use recursion to check other possible combo
    if not last_try:
        return get_user_pair_id(user2, user1, True)

    # not found, add the pair id and return it
    return add_user_pair(user1, user2)

def add_user_pair(user1, user2):
    """
    Add user pair entry for user1 and user2
    Returns user pair id (int)
    """
    max_query = "SELECT MAX(id) FROM UserPair"
    user1_id = get_user_id(user1)
    user2_id = get_user_id(user2)

    query = """
    INSERT OR IGNORE INTO UserPair
    (id, user1, user2)  
    VALUES
    (?, ?, ?)
    """

    db = get_db()
    cur = db.cursor()
    cur.execute(max_query)
    result = cur.fetchone()[0]
    if not result:
        new_id = 1
    else:
        new_id = int(result) + 1

    cur.execute(query, (new_id, user1_id, user2_id))
    #cur.execute(query, (new_id, user2_id, user1_id))

    db.commit()

    return new_id

def get_user_id(username):
    """
    Gets user id for a username
    Returns user id (int)
    """
    query = """
    SELECT id
    FROM Users
    WHERE username = ?
    """
    db = get_db()
    cur = db.cursor()
    cur.execute(query, (username,))
    result = cur.fetchone()
    if result:
        return result[0]

    return None

def get_totals(username):
    """
    Gets running totals for a username
    One to many relationship, username to any expenses
        with another user
    Returns a dictionary with totals
    """
    user_id = get_user_id(username)
    my_pairs = get_my_user_pairs(session["username"])
    query = """
    SELECT up.user1, up.user2, debtor_id, amount, o.id
    FROM RunningTotal rt
    JOIN UserPair up
        ON up.id = rt.pair_id
    LEFT JOIN Opened o
        ON o.id = rt.last_opened_id
    WHERE rt.pair_id IN {0}
    ORDER BY rt.id ASC

    """
    pairs_str = '(' + ','.join(map(str, my_pairs)) + ')'
    query = query.format(pairs_str)
    app.logger.debug(query)

    db = get_db()
    cur = db.cursor()
    cur.execute(query)
    totals = {}
    for row in cur.fetchall():
        user1, user2, debtor_id, amount, opened = row
        app.logger.debug("%s,%s,%s,%s,%s", username, user_id, debtor_id, user1, user2)

        if user1 != user_id:
            second_user = get_username(user1)
        else:
            second_user = get_username(user2)

        if not opened:
            opened = "No one"
        elif opened == user_id: 
            opened = "You"
        else:
            opened = second_user

        if debtor_id == user_id:
            in_debt = True
        else:
            in_debt = False

        amount = "{0:.2f}".format(round(amount,2))
        totals[second_user] = {"amount": amount, "opened": opened, "in_debt": in_debt}
        app.logger.debug(totals[second_user])

    app.logger.debug(totals)
    return totals

def update_running_total(pair_id, debtor_id, amount, opened_id):
    """
    Given an expense, update the running total
    """
    query = """
    SELECT id, debtor_id, amount FROM RunningTotal
    WHERE pair_id = ?
    """
    db = get_db()
    cur = db.cursor()
    cur.execute(query, (pair_id,))
    result = cur.fetchone()

    # already exists
    if result:
        total_id, cur_debtor_id, cur_amount = result
        cur_amount = float(cur_amount)
        amount = float(amount)

        # user (cur_debtor_id) is in debt currently, but loaned
        if int(cur_debtor_id) != debtor_id:
            amount = cur_amount - amount
            # if amount is negative, then user no longer in debt
            if amount < 0:
                amount = abs(amount)
            else:
                # otherwise still in debt
                debtor_id = cur_debtor_id
        else:
            # user (cur_debtor_id) still in debt
            amount += cur_amount
            debtor_id = cur_debtor_id

        if opened_id:
            query = """
            UPDATE RunningTotal
            SET debtor_id = ?,
            amount = ?,
            last_opened_id = ?
            WHERE id = ?
            """
            cur.execute(query, (debtor_id, amount, opened_id, total_id))
        else:
            query = """
            UPDATE RunningTotal
            SET debtor_id = ?,
            amount = ?
            WHERE id = ?
            """
            cur.execute(query, (debtor_id, amount, total_id))
        
    else: # doesn't exist
            query = """
            INSERT INTO RunningTotal
            (pair_id, debtor_id, amount, last_opened_id)
            VALUES
            (?, ?, ?, ?)
            """
            cur.execute(query, (pair_id, debtor_id, amount, opened_id))

    db.commit()

@app.route('/')
@app.route('/expenses')
def expenses():
    """
    Show the home page if logged in
    If not logged in, redirect
    """
    logged_in = session.get('logged_in', None)
    if logged_in is True:
        totals = get_totals(session["username"])
        return render_template('expenses.html', username=session["username"], totals=totals)

    return render_template('login.html', error="You are not logged in!")

def amount_to_dollars_cents(amount):
    try:
        dollars, cents = amount.split('.')
        if len(dollars) == 0:
            dollars = 0
        try:
            int(dollars)
            int(cents)
            return dollars, cents
        except ValueError as e:
            return render_template("new.html", error=e, username=session["username"])
    except ValueError:
        try:
            int(amount)
            return amount, 0
        except ValueError as e:
            return render_template("new.html", error=e, username=session["username"])


@app.route("/new", methods=['GET', 'POST'])
def add_expense():
    """
    Adds a new expense for current username
    """
    logged_in = session.get('logged_in', None)
    if not logged_in:
        return render_template('login.html', error="You are not logged in!")

    msg = None

    if request.method == 'POST':
        amount = request.form.get("amount", None)
        amount = simple_eval(amount)
        my_username = session["username"]
        my_id = get_user_id(my_username)
        second_username = request.form.get("expense_user", None)
        pair_id = get_user_pair_id(my_username, second_username)
        second_id = get_user_id(second_username)
        expense_method = request.form.get("expense_method", None)
        reason = request.form.get("reason", None)
        ts = int(time.time())
        if expense_method == "lessor":
            lessor_id = my_id
            debtor_id = second_id
        else:
            lessor_id = second_id
            debtor_id = my_id

        query = """
        INSERT INTO Expenses 
        (timestamp, pair_id, lessor_id, amount, reason)
        VALUES
        (?, ?, ?, ?, ?)
        """
        
        db = get_db()
        cur = db.cursor()
        cur.execute(query, (ts, pair_id, lessor_id, amount, reason))
        expense_id = cur.lastrowid
        db.commit()

        # check who opened the door last
        i_opened = request.form.getlist("i_opened")
        they_opened = request.form.getlist("they_opened")
        if i_opened and they_opened:
            raise Exception("You can't both open the door!")

        opened_id = None
        if i_opened:
            opened_id = my_id
        elif they_opened:
            opened_id = second_id

        if opened_id:
            query = """
            INSERT INTO Opened
            (expense_id, user_id)
            VALUES
            (?, ?)
            """

            cur.execute(query, (expense_id, opened_id))
            db.commit()

        update_running_total(pair_id, debtor_id, amount, opened_id)
        msg = "Added expense!"

    users = get_all_users()

    return render_template('new.html', users=users, username=session["username"], msg=msg)

@app.route("/user", methods=['GET', 'POST'])
def user():
    """
    Creates a new user
    If already logged in, shows an error
    """
    if request.method == 'POST':
        try:
            username = request.form.get("username", None)
            password = request.form.get("password", None)
            add_user(username, password)
            session['username'] = username
            session['logged_in'] = True
            return redirect(url_for("expenses"))
        except Exception as e:
            error = "Error: {0}".format(e)
            return render_template("user.html", error=error)

    logged_in = session.get('logged_in', None)
    if logged_in:
        error = "You are already logged in!"
        return render_template("user.html", error=error, username=session["username"])

    return render_template("user.html", username=session["username"])

@app.route("/expenses/delete/<expense_id>")
def delete_expense(expense_id):
    """
    Deletes an expense from the list
    @TODO: email/notify second party?
    """
    query = """
    SELECT up.user1, up.user2, pair_id, lessor_id, amount, o.user_id
    FROM Expenses e
    JOIN UserPair up
        ON up.id = e.pair_id
    LEFT JOIN Opened o
        ON e.id = o.expense_id
    WHERE e.id = ?
    """
    db = get_db()
    cur = db.cursor()
    cur.execute(query, (expense_id,))
    result = cur.fetchone()
    if result:
        app.logger.debug(result)
        user1, user2, pair_id, lessor_id, amount, opened_id = result
        if user1 == lessor_id:
            debtor_id = user2
        else:
            debtor_id = user1
    else:
        return redirect(url_for("all_expenses"))

    query = """
    DELETE FROM Expenses
    WHERE id = ?
    """

    cur.execute(query, (expense_id,))
    db.commit()
    cur.close()

    update_running_total(pair_id, lessor_id, amount, opened_id)

    return redirect(url_for("all_expenses"))

def timestamp_to_local_date_string(unix_timestamp):
    """
    Convert unix timestamp to local timestamp
    Return date string
    """
    utc_dt = datetime.fromtimestamp(
        int(unix_timestamp)
    )
    local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
    local_dt = local_tz.normalize(local_dt)

    return local_dt.strftime('%Y-%m-%d %H:%M:%S')

@app.route("/all")
def all_expenses():
    """
    List all expenses for current user
    Returns a list of all expenses
    """
    db = get_db()
    cur = db.cursor()
    my_pairs = get_my_user_pairs(session["username"])
    my_id = get_user_id(session["username"])
    query = """
    SELECT e.id, timestamp, up.user1, up.user2, lessor_id, amount, reason, o.user_id
    FROM Expenses e
    JOIN UserPair up
        ON up.id = e.pair_id
    LEFT JOIN Opened o
        ON o.expense_id = e.id
    WHERE e.pair_id IN {0}
    ORDER BY e.id DESC
    """

    pairs_str = '(' + ','.join(map(str, my_pairs)) + ')'
    query = query.format(pairs_str)
    app.logger.debug(query)
    cur.execute(query)
    expenses = []

    for row in cur.fetchall():
        expense_id, ts, user1, user2, lessor, amount, reason, opened_user_id = row
        if user1 != my_id:
            username = get_username(user1)
        else:
            username = get_username(user2)

        if opened_user_id:
            if opened_user_id == my_id:
                opened = "You"
            else:
                opened = username
        else:
            opened = "No one"

        # I was loaned money, value is negative
        if lessor != my_id:
            in_debt = True
        else:
            in_debt = False

        date_string = timestamp_to_local_date_string(ts) 
        expenses.append({"username": username, "date": date_string, "amount": amount, "reason": reason, "opened": opened, "in_debt": in_debt, "expense_id": expense_id})
    return render_template('all.html', expenses=expenses, username=session["username"])

def get_my_user_pairs(username):
    """
    Get all user pair ids for current username
    Returns a list of all pair ids
    """
    query = """
    SELECT up.id
    FROM UserPair up
    JOIN Users u
        ON u.id = up.user1
        OR u.id = up.user2
    WHERE u.username = ?
    """

    db = get_db()
    cur = db.cursor()
    cur.execute(query, (username,))
    pairs = [pair[0] for pair in cur.fetchall()]
    return pairs

@app.route("/logout")
def logout():
    """
    Logout of expenses site
    Redirect to login page
    """
    session['logged_in'] = False
    session['username'] = None
    return redirect(url_for("login"))

@app.route("/login", methods=['GET', 'POST'])
def login():
    """
    Login to expenses page
    Validate username/pw
    """
    error = None
    if request.method == 'POST':
        username = request.form.get("username", None)
        password = request.form.get("password", None)
        if validate_login(username, password):
            session['username'] = username
            session['logged_in'] = True
            flash('Logged in')
            return redirect(url_for('expenses'))

        return render_template('login.html', error="Invalid login")

    return render_template('login.html')

def validate_login(username, password):
    """
    Validate login by checking password for
        current username
    """
    hashed = hash_password(password)
    db = get_db()
    cur = db.cursor()
    cur.execute('select password from Users where username = ?', (username,))
    result = cur.fetchone()
    if result:
        db_pw = result[0]
        if db_pw == hashed:
            return True

    return False

def hash_password(password):
    """
    Basic hash of password in md5
    Use salt from config
    """
    password = password.encode('utf-8')
    salt = app.config['SECRET_KEY']
    return hashlib.md5(salt + password).hexdigest()

def user_exists(username):
    """
    Check if user exists in db
    True if user exists
    False if user doesn't exist
    """
    db = get_db()
    cur = db.cursor()
    cur.execute("select username from Users where username = ?", (username,))
    if cur.fetchone() is None:
        return False

    return True

def add_user(username, password):
    """
    Add user to database
    """
    if user_exists(username):
        raise Exception("user exists")

    hashed = hash_password(password)
    db = get_db()
    cur = db.cursor()
    cur.execute('insert into Users (username, password) values (?, ?)', (username, hashed))
    db.commit()
    flash("User added successfully")

@app.route("/changepw", methods=["GET", "POST"])
def change_password():
    """
    Change password of current user
    """
    if request.method == 'POST':
        password = request.form.get("password", None)
        app.logger.debug(password)
        if password:
            update_password(password)
        return redirect(url_for('expenses'))

    return render_template('change_password.html')

def update_password(password):
    """
    Update password in database for current user
    """
    my_id = get_user_id(session["username"])
    hashed = hash_password(password)
    query = """
    UPDATE Users
    SET password = ?
    WHERE id = ?
    """
    app.logger.debug("%s\n%s\n%s\n%s", query, password, hashed, my_id)
    db = get_db()
    cur = db.cursor()
    cur.execute(query, (hashed, my_id))
    db.commit()

if __name__ == "__main__":
    handler = logging.FileHandler(app.config['LOG_FILE'])
    fmtr = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(fmtr)
    handler.setLevel(logging.DEBUG)
    app.logger.addHandler(handler)
    app.logger.debug("Starting up")
    app.debug = True
    app.run(host=app.config['HOST'], port=app.config['PORT'])
