
# app.py -- VULNERABLE: educational only (modified to support UNION/SELECT learning)
from flask import Flask, request, render_template_string, g, redirect, url_for, session
import sqlite3, os, secrets

DB = os.path.join(os.path.dirname(__file__), "ctf.db")

def load_secret_key():
    val = os.environ.get("FLASK_SECRET_KEY")
    if val:
        return val

    raise Exception("SECRET KEY NOT FOUND")


app = Flask(__name__)
app.secret_key = load_secret_key()

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB)
        db.row_factory = sqlite3.Row
    return db

@app.route("/")
def index():
    return """
        <h2>Classic SQL</h2>
        <p><a href="/login">Login</a></p>
        <p>The flag is divided into two parts. Good luck players!<br>
        Tip: Try the single quotation.</p>
    """

# --- login route (vulnerable on purpose) ---
@app.route("/login", methods=["GET","POST"])
def login():
    msg = ""
    if request.method == "POST":
        user = request.form.get("username", "")
        pwd  = request.form.get("password", "")

        # intentionally vulnerable SQL
        sql = "SELECT id, username FROM users WHERE username = '%s' AND password = '%s'" % (user, pwd)
        print("DEBUG SQL:", sql)

        try:
            # fetch all matching rows
            rows = get_db().execute(sql).fetchall()
        except Exception as e:
            return f"<h3>DB error:</h3><pre>{e}</pre><p><a href='/login'>back</a></p>"

        username = None
        if rows:
            # search for cusis first
            for r in rows:
                if r["username"] == "cusis":
                    username = "cusis"
                    break
            # if no cusis, take the first row
            if not username:
                username = rows[0]["username"]
            
        # redirect / render based on username
        if username == "cusis":
            session["logged_in"] = True
            return redirect(url_for("cusis"))
        elif username == "admin":
            return redirect(url_for("admin", u=username))
        elif username:
            return render_template_string("""
                <h3>Welcome {{username}}</h3>
                <p>This is a normal user page.</p>
                <p><a href='/'>home</a></p>
            """, username=username)
        else:
            msg = "Login failed"

    return render_template_string("""
        <h3>CUSIS Login</h3>
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
        <p style="color:red;">{{msg}}</p>
        <p><a href="/">Home</a></p>
    """, msg=msg)

@app.route("/cusis")
def cusis():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    # now safe to show dashboard
    cur = get_db().execute("SELECT flag_part1 FROM secrets LIMIT 1")
    row = cur.fetchone()
    flag1 = row["flag_part1"] if row else "No flag found"
    return f"""<h3>CUSIS dashboard</h3>
            <pre>{flag1}</pre>
            <p>Try go the search page for the second half of the flag!!!</p>
            <p><a href='/'>Home</a><br>
                <a href='/login'>Login</p>"""

@app.route("/admin")
def admin():
    return """<h3>Fake flag:</h3>
        <strong>cuhk25ctf{th1s_1s_n0t_r34l}</strong>
        <p>I know "admin" as a username is also classic, but I wanna try something interesting here :)</p>
        <p><a href='/'>Home</a><br> <a href='/login'>Login</a></p>"""

@app.route("/search")
def search():
    # Get query parameter 'q', strip whitespace
    q = request.args.get("q", "").replace("%", "")

    # Start building page output
    out = "<h3>Search Users</h3>"

    if q:
        # --- VULNERABLE SQL (educational only) ---
        sql = "SELECT username, note FROM private_notes WHERE username LIKE '%s'" % q
        try:
            print("DEBUG SQL (search):", sql)
            cur = get_db().execute(sql)
            rows = cur.fetchall()
        except Exception as e:
            return f"<h3>DB error:</h3><pre>{e}</pre><p><a href='/'>home</a></p>"

        if rows:
            for r in rows:
                out += f"<div><strong>{r['username']}</strong>: <pre>{r['note']}</pre></div>"
        else:
            out += "<p>No results found</p>"
    else:
        out += "<p>Select a suitable user to search.</p>"

    # Add the search form at the bottom
    out += """
        <p>Use /search?q=[your_input] in the URL to search for the second half of the flag~<br>
        Or you can use the technique that you just use in part 1. They are all classic SQL injection ;)</p>
    """

    return out

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

if __name__ == "__main__":
    # create DB if missing
    if not os.path.exists(DB):
        os.system("python3 init_db.py")
    app.run(host="0.0.0.0", port=8080)
