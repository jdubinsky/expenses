#!/usr/bin/python3

import sqlite3
from contextlib import closing
from flask import Flask, request, session, g, redirect, url_for, \
             abort, render_template, flash
import hashlib, uuid
from flask_bootstrap import Bootstrap
import time
import datetime

app = Flask(__name__)
Bootstrap(app)

app.config.from_object("config")

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])

    return db

"""
def init_db():
    with closing(connect_db()) as db:
        with app.open_resource("schema.sql", mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
"""

def get_all_users():
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

def get_user_pair_id(user1, user2):
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

    return add_user_pair(user1, user2)

def add_user_pair(user1, user2):
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
    cur.execute(query, (new_id, user2_id, user1_id))

    db.commit()

    return new_id

def get_user_id(username):
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
    user_id = get_user_id(username)
    query = """
    SELECT u.username, total_dollars, total_cents, o.id
    FROM RunningTotal rt
    LEFT JOIN Opened o
        ON o.id = rt.last_opened_id
    JOIN UserPair up
        ON rt.pair_id = up.id
    JOIN Users u
        ON u.id = up.user2
    WHERE up.user1 = ?
    """

    db = get_db()
    cur = db.cursor()
    cur.execute(query, (user_id,))
    totals = []
    for row in cur.fetchall():
        second_user, dollars, cents, opened = row
        if not opened:
            opened = "No one"
        elif opened == user_id: 
            opened = username
        else:
            opened = second_user

        amount = "{0}.{1}".format(dollars, cents)
        totals.append({"username": second_user, "amount": amount, "opened": opened})

    return totals

def update_running_total(pair_id, dollars, cents, opened_id):
    query = """
    SELECT id, total_dollars, total_cents FROM RunningTotal
    WHERE pair_id = ?
    """
    db = get_db()
    cur = db.cursor()
    cur.execute(query, (pair_id,))
    result = cur.fetchone()
    # already exists
    if result:
        if opened_id:
            total_id = result[0]
            query = """
            UPDATE RunningTotal
            SET total_dollars = ?,
            total_cents = ?,
            opened_id = ?
            WHERE id = ?
            """
            cur.execute(query, (dollars, cents, opened_id, total_id))
        else:
            query = """
            UPDATE RunningTotal
            SET total_dollars = ?,
            total_cents = ?,
            WHERE id = ?
            """
            cur.execute(query, (dollars, cents, total_id))
        
    else: # doesn't exist
            query = """
            INSERT INTO RunningTotal
            (pair_id, total_dollars, total_cents, last_opened_id)
            VALUES
            (?, ?, ?, ?)
            """
            cur.execute(query, (pair_id, dollars, cents, opened_id))

    db.commit()

@app.route('/')
@app.route('/expenses')
def expenses():
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
            return render_template("new.html", error=e)
    except ValueError:
        try:
            int(amount)
            return amount
        except ValueError as e:
            return render_template("new.html", error=e)


@app.route("/new", methods=['GET', 'POST'])
def add_expense():
    logged_in = session.get('logged_in', None)
    if not logged_in:
        return render_template('login.html', error="You are not logged in!")

    if request.method == 'POST':
        amount = request.form.get("amount", None)
        dollars, cents = amount_to_dollars_cents(amount)
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
        else:
            lessor_id = second_id
        query = """
        INSERT INTO Expenses 
        (timestamp, pair_id, lessor_id, amount_dollars, amount_cents, reason)
        VALUES
        (?, ?, ?, ?, ?, ?)
        """
        
        db = get_db()
        cur = db.cursor()
        cur.execute(query, (ts, pair_id, lessor_id, dollars, cents, reason))
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

        update_running_total(pair_id, dollars, cents, opened_id)

        flash("Expense added!")

    users = get_all_users()

    return render_template('new.html', users=users)

@app.route("/user", methods=['GET', 'POST'])
def user():
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
        return render_template("user.html", error=error)

    return render_template("user.html")

#@app.route("/expenses/delete")

def timestamp_to_local_date_string(timestamp):
    dt = datetime.datetime.fromtimestamp(
        int(timestamp)
    )
    dt = dt.replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
    return dt.strftime('%Y-%m-%d %H:%M:%S')


@app.route("/all")
def all_expenses():
    db = get_db()
    cur = db.cursor()
    #my_pairs = get_my_user_pairs(session["username"])
    my_id = get_user_id(session["username"])
    query = """
    SELECT timestamp, u.username, amount_dollars, amount_cents, reason, o.user_id
    FROM Expenses e
    JOIN UserPair up
        ON e.pair_id = up.id
    JOIN Users u
        ON up.user2 = u.id
    LEFT JOIN Opened o
        ON o.expense_id = e.id
    WHERE up.user1 = ?
    """
    cur.execute(query, (my_id,))
    expenses = []
    for row in cur.fetchall():
        ts, username, dollars, cents, reason, opened_user_id = row
        if opened_user_id:
            if opened_user_id == my_id:
                opened = "You"
            else:
                opened = username
        date_string = timestamp_to_local_date_string(ts) 
        amount = "{0}.{1}".format(dollars, cents)
        expenses.append({"username": username, "date": date_string, "amount": amount, "reason": reason, "opened": opened})
    return render_template('all.html', expenses=expenses, username=session["username"])

def get_my_user_pairs(username):
    query = """
    SELECT up.id
    FROM UserPair up
    JOIN Users u
        ON u.id = up.user1
    WHERE u.username = ?
    """

    db = get_db()
    cur = db.cursor()
    cur.execute(query)
    pairs = [pair for pair[0] in cur.fetchall()]
    return pairs

@app.route("/logout")
def logout():
    session['logged_in'] = False
    return redirect(url_for("login"))

@app.route("/login", methods=['GET', 'POST'])
def login():
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
    password = password.encode('utf-8')
    #salt = uuid.uuid4().hex
    #hashed_password = hashlib.sha512(password.encode('utf-8') + salt.encode('utf-8')).hexdigest()
    #hashed = hashlib.sha512(password + salt).hexdigest()

    m = hashlib.md5()
    m.update(password)
    hashed = m.hexdigest()
    return hashed

def user_exists(username):
    db = get_db()
    cur = db.cursor()
    cur.execute("select username from Users where username = ?", (username,))
    if cur.fetchone() is None:
        return False

    return True

def add_user(username, password):
    if user_exists(username):
        raise Exception("user exists")

    hashed = hash_password(password)
    db = get_db()
    cur = db.cursor()
    cur.execute('insert into Users (username, password) values (?, ?)', (username, hashed))
    db.commit()
    flash("User added successfully")

if __name__ == "__main__":
    app.debug = True
    app.run()
