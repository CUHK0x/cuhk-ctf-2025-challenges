# init_db.py (idempotent + --reinit)
import sqlite3, os, argparse

DB = os.path.join(os.path.dirname(__file__), "ctf.db")
parser = argparse.ArgumentParser()
parser.add_argument("--reinit", action="store_true", help="Delete existing DB and recreate")
args = parser.parse_args()

if args.reinit and os.path.exists(DB):
    os.remove(DB)
    print("Removed existing DB (reinit)")

conn = sqlite3.connect(DB)
c = conn.cursor()

# users table
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
)
""")
c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("cusis", "verysecretpass"))
c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("admin", "fakeflag1234"))
for i in range(1, 21):
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", (f"user{i}", f"pass{i}"))

# secrets table + ensure flag_part1 exists
c.execute("""
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY,
    flag_part1 TEXT
)
""")
# use INSERT OR REPLACE to guarantee the row exists/updated
c.execute("INSERT OR REPLACE INTO secrets (id, flag_part1) VALUES (?, ?)",
          (1, "cuhk25ctf{SQL_1s_"))

# private_notes table + special note
c.execute("""
CREATE TABLE IF NOT EXISTS private_notes (
    id INTEGER PRIMARY KEY,
    username TEXT,
    note TEXT
)
""")
c.execute("INSERT OR REPLACE INTO private_notes (id, username, note) VALUES (?, ?, ?)",
          (1, "CUSIS", "N0t_Th4t_HaRd_1o1}"))

conn.commit()
conn.close()
print("DB initialized/updated. Use --reinit to recreate from scratch.")
