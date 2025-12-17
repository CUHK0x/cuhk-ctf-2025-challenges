from flask import Flask, render_template, request, send_file, session, g
from PIL import Image, ImageFont, ImageDraw, ImageFilter
import glob
import hashlib
import io
import logging
import os
import psycopg2
import secrets
import shutil
import string
import tarfile
import time

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.logger.setLevel(
    logging.getLevelNamesMapping().get(os.getenv("LOGGING_LEVEL", "INFO"))
)


OUTDATED_RECORDS_AGE_LIMIT_MINUTES = 10


def connect_to_postgres():
    if 'db' not in g: 
        try:
            g.db = psycopg2.connect(
                dbname=os.environ.get("DB_NAME") or "database",
                user=os.environ.get("DB_USER") or "postgres",
                password=os.environ.get("DB_PASSWORD") or "password",
                host=os.environ.get("DB_HOST") or "localhost",
                port=os.environ.get("DB_PORT") or "5432",
            )
        except psycopg2.Error as e:
            raise e
    return g.db


def disconnect_from_postgres(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()
        
app.teardown_appcontext(disconnect_from_postgres) 


def clear_old_captchas(
    connection, age_limit_minutes=OUTDATED_RECORDS_AGE_LIMIT_MINUTES
):
    cursor = connection.cursor()
    cursor.execute(
        f"DELETE FROM captchas WHERE created_at < NOW() - INTERVAL '{age_limit_minutes} minutes';"
    )
    connection.commit()
    cursor.close()


@app.get("/")
def home():
    return render_template("index.html")


@app.route("/uploads/<upload_id>", defaults={"route": ""})
@app.route("/uploads/<upload_id>/<path:route>")
def uploads(upload_id, route):
    upload_dir = os.path.abspath(os.path.join("uploads", upload_id, route))
    if not os.path.exists(upload_dir):
        return "Upload not found.", 404
    elif not upload_dir.startswith(os.path.abspath("uploads") + os.sep):
        return "Forbidden.", 403

    conn = connect_to_postgres()
    cursor = conn.cursor()
    cursor.execute("SELECT owned_by FROM uploads WHERE id = %s", (upload_id,))
    record = cursor.fetchone()
    if record is None or session.get("user") != record[0]:
        return "Forbidden.", 403
    cursor.close()

    if os.path.isfile(upload_dir):
        with open(upload_dir, "rb") as f:
            return send_file(
                io.BytesIO(f.read()),
                download_name=os.path.basename(upload_dir),
                as_attachment=True,
            )

    return render_template(
        "uploads.html",
        uploads=sorted(os.listdir(upload_dir)),
        upload_id=upload_id,
        route=route,
    )


@app.get("/api/captcha")
def captcha():
    name = request.args.get("name")
    length = request.args.get("length")
    if (
        name is None
        or length is None
        or not length.isdigit()
        or int(length) <= 0
        or int(length) > 1000
    ):
        return "Missing or incorrect parameters", 400
    length = int(length)

    image = Image.new("RGB", (200, 80), (255, 255, 255))
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype("FreeMono.ttf", 150)
    alphabet = string.ascii_letters + string.digits
    captcha = "".join(secrets.choice(alphabet) for _ in range(length))

    conn = connect_to_postgres()
    clear_old_captchas(conn)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO captchas (id, captcha) VALUES (%s, %s) ON CONFLICT (id) DO UPDATE SET captcha = EXCLUDED.captcha;",
        (
            name,
            captcha,
        ),
    )
    conn.commit()
    cursor.close()

    for character in captcha:
        draw.text(
            (100, 40),
            character,
            (0, 0, 0),
            font=font,
            spacing=0,
            align="center",
            anchor="mm",
        )
    blurred_image = image.filter(ImageFilter.GaussianBlur(radius=5))
    draw2 = ImageDraw.Draw(blurred_image)
    font = ImageFont.truetype("FreeMono.ttf", 100)
    draw2.text(
        (100, 40),
        "OWO",
        (0, 200, 50),
        font=font,
        spacing=0,
        align="center",
        anchor="mm",
    )
    byte_arr = io.BytesIO()
    blurred_image.save(byte_arr, format="PNG")
    byte_arr.seek(0)
    return send_file(byte_arr, mimetype="image/png")


@app.post("/api/login")
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    if username is None or password is None:
        return "Username and password are required.", 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = connect_to_postgres()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = %s AND password = %s",
        (username, password_hash),
    )
    user = cursor.fetchone()
    cursor.close()
    if user:
        session["user"] = username
        return "Login successful.", 200

    return "Invalid credentials.", 401


@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return "Logout successful.", 200


@app.post("/api/register")
def register():
    username = request.json.get("username")
    password = request.json.get("password")
    if not username or not password:
        return "Username and password are required.", 400
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = connect_to_postgres()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, password_hash),
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        cursor.close()
        return "Username already exists.", 400
    cursor.close()
    return "Registration successful.", 201


@app.get("/api/me")
def me():
    if session.get("user") is None:
        return "Unauthorized.", 401
    return session["user"], 200


@app.get("/api/flag")
def flag():
    if session.get("user") is None:
        return "Unauthorized.", 401

    username = session["user"]
    conn = connect_to_postgres()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT flag FROM users WHERE username = %s",
        (username,),
    )
    result = cursor.fetchone()
    cursor.close()
    if result:
        return result[0], 200
    return "Flag not found.", 404


@app.post("/api/upload")
def upload():
    if session.get("user") is None:
        return "Unauthorized.", 401

    file = request.files.get("file")
    if not file:
        return "No files are found.", 400
    captcha_id = request.form.get("captcha_id")
    captcha_solution = request.form.get("captcha_solution")

    if not captcha_id or not captcha_solution:
        return "Invalid CAPTCHA.", 400

    conn = connect_to_postgres()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT captcha FROM captchas WHERE id = %s",
        (captcha_id,),
    )
    record = cursor.fetchone()
    if not record or record[0] != captcha_solution:
        cursor.close()
        return "Invalid CAPTCHA.", 400

    outdated_time = time.time() - OUTDATED_RECORDS_AGE_LIMIT_MINUTES * 60
    cursor.execute(
        "SELECT id FROM uploads WHERE uploaded_at < TO_TIMESTAMP(%s);", (outdated_time,)
    )
    outdated_records = cursor.fetchall()
    for upload_id in outdated_records:
        shutil.rmtree(os.path.join("uploads", upload_id[0]), ignore_errors=True)
    cursor.execute(
        "DELETE FROM uploads WHERE uploaded_at < TO_TIMESTAMP(%s);", (outdated_time,)
    )
    conn.commit()
    cursor.close()

    if tarfile.is_tarfile(file):
        with tarfile.open(fileobj=file, mode="r:*") as tar:
            upload_id = secrets.token_hex(16)
            extract_dir = os.path.join("uploads", upload_id)
            shutil.rmtree(extract_dir, ignore_errors=True)
            os.makedirs(extract_dir, exist_ok=True)

            for child in tar.getnames():
                target_path = os.path.abspath(os.path.join(extract_dir, child))

                if not target_path.startswith(os.path.abspath(extract_dir) + os.sep):
                    return "Invalid file path", 400

            tar.extractall(extract_dir)
            conn = connect_to_postgres()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO uploads (id, owned_by) VALUES (%s, %s)",
                (upload_id, session["user"]),
            )
            conn.commit()
            cursor.close()
        return upload_id, 200
    return "Only .tar files are allowed.", 400
