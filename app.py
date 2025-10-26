import os
import sqlite3
import uuid
import json
from datetime import timedelta
from flask import (Flask, g, render_template, request, redirect,
                   url_for, session, flash, send_from_directory, jsonify)
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from google import genai
from PyPDF2 import PdfReader

# Load environment variables
load_dotenv()

# ----------------------
# CONFIG
# ----------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "png", "jpg", "jpeg"}

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
Session(app)

DATABASE = os.path.join(BASE_DIR, "lms.db")

# ----------------------
# GEMINI API HELPER
# ----------------------
client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

def call_gemini_api(prompt, system_prompt=None):
    full_prompt = (system_prompt + "\n\n" + prompt) if system_prompt else prompt
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=full_prompt
    )
    # Return raw text, no JSON parsing
    return response.text.strip()

# ----------------------
# DB HELPERS
# ----------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('teacher','student'))
    );
    CREATE TABLE IF NOT EXISTS classes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        code TEXT UNIQUE NOT NULL,
        teacher_id INTEGER NOT NULL,
        FOREIGN KEY(teacher_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS class_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        class_id INTEGER NOT NULL,
        student_id INTEGER NOT NULL,
        UNIQUE(class_id, student_id),
        FOREIGN KEY(class_id) REFERENCES classes(id),
        FOREIGN KEY(student_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        class_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        points INTEGER DEFAULT 100,
        FOREIGN KEY(class_id) REFERENCES classes(id)
    );
    CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assignment_id INTEGER NOT NULL,
        student_id INTEGER NOT NULL,
        filename TEXT,
        text TEXT,
        grade REAL,
        feedback TEXT,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(assignment_id, student_id),
        FOREIGN KEY(assignment_id) REFERENCES assignments(id),
        FOREIGN KEY(student_id) REFERENCES users(id)
    );
    """)
    db.commit()

with app.app_context():
    init_db()

# ----------------------
# UTILS
# ----------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def query_one(query, args=()):
    cur = get_db().execute(query, args)
    row = cur.fetchone()
    cur.close()
    return row

def query_all(query, args=()):
    cur = get_db().execute(query, args)
    rows = cur.fetchall()
    cur.close()
    return rows

def class_folder(class_id):
    folder = os.path.join(app.config["UPLOAD_FOLDER"], f"class_{class_id}")
    os.makedirs(folder, exist_ok=True)
    return folder

# ----------------------
# AUTH
# ----------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role = request.form.get("role")
        if not username or not password or role not in ("teacher", "student"):
            flash("Please complete all fields.", "warning")
            return redirect(url_for("signup"))
        pw_hash = generate_password_hash(password)
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       (username, pw_hash, role))
            db.commit()
            flash("Account created — please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken.", "danger")
            return redirect(url_for("signup"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = query_one("SELECT * FROM users WHERE username = ?", (username,))
        if user and check_password_hash(user["password_hash"], password):
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Logged in", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))

# ----------------------
# DASHBOARD
# ----------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] == "teacher":
        classes = query_all("SELECT * FROM classes WHERE teacher_id = ?", (session["user_id"],))
        return render_template("teacher_dashboard.html", classes=classes)
    else:
        classes = query_all(
            "SELECT c.* FROM classes c JOIN class_members m ON c.id = m.class_id WHERE m.student_id = ?",
            (session["user_id"],)
        )
        return render_template("student_dashboard.html", classes=classes)

# ----------------------
# CLASS MANAGEMENT
# ----------------------
@app.route("/create_class", methods=["GET", "POST"])
def create_class():
    if session.get("role") != "teacher":
        flash("Only teachers can create classes.", "danger")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form["name"].strip()
        if not name:
            flash("Name required", "warning")
            return redirect(url_for("create_class"))
        code = uuid.uuid4().hex[:8].upper()
        db = get_db()
        db.execute("INSERT INTO classes (name, code, teacher_id) VALUES (?, ?, ?)",
                   (name, code, session["user_id"]))
        db.commit()
        flash(f"Class '{name}' created. Code: {code}", "success")
        return redirect(url_for("dashboard"))
    return render_template("create_class.html")

@app.route("/join_class", methods=["GET", "POST"])
def join_class():
    if session.get("role") != "student":
        flash("Only students can join classes.", "danger")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        code = request.form["code"].strip().upper()
        cls = query_one("SELECT * FROM classes WHERE code = ?", (code,))
        if not cls:
            flash("Invalid class code.", "danger")
            return redirect(url_for("join_class"))
        try:
            db = get_db()
            db.execute("INSERT INTO class_members (class_id, student_id) VALUES (?, ?)",
                       (cls["id"], session["user_id"]))
            db.commit()
            flash(f"Joined class {cls['name']}", "success")
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("Already a member of this class.", "info")
            return redirect(url_for("dashboard"))
    return render_template("join_class.html")

# ----------------------
# CLASS DETAIL & FILES
# ----------------------
@app.route("/class/<int:class_id>")
def class_detail(class_id):
    cls = query_one("SELECT * FROM classes WHERE id = ?", (class_id,))
    if not cls:
        flash("Class not found", "danger")
        return redirect(url_for("dashboard"))

    folder_path = class_folder(class_id)
    try:
        uploaded_files = os.listdir(folder_path)
    except FileNotFoundError:
        uploaded_files = []

    if session.get("role") == "teacher" and cls["teacher_id"] == session["user_id"]:
        assignments = query_all("SELECT * FROM assignments WHERE class_id = ?", (class_id,))
        students = query_all(
            "SELECT u.* FROM users u JOIN class_members m ON u.id = m.student_id WHERE m.class_id = ?",
            (class_id,)
        )
        return render_template(
            "class_detail_teacher.html",
            cls=cls,
            assignments=assignments,
            students=students,
            uploaded_files=uploaded_files
        )

    member = query_one(
        "SELECT * FROM class_members WHERE class_id = ? AND student_id = ?",
        (class_id, session["user_id"])
    )
    if not member:
        flash("You are not a member of this class.", "danger")
        return redirect(url_for("dashboard"))

    assignments = query_all("SELECT * FROM assignments WHERE class_id = ?", (class_id,))
    submissions = query_all(
        "SELECT * FROM submissions WHERE student_id = ?", (session["user_id"],)
    )
    submissions_dict = {sub["assignment_id"]: sub for sub in submissions}

    return render_template(
        "class_detail_student.html",
        cls=cls,
        assignments=assignments,
        submissions_dict=submissions_dict,
        uploaded_files=uploaded_files
    )

@app.route("/class/<int:class_id>/upload", methods=["POST"])
def upload_file(class_id):
    if "user_id" not in session or session.get("role") != "teacher":
        flash("Not authorized", "danger")
        return redirect(url_for("dashboard"))

    cls = query_one("SELECT * FROM classes WHERE id = ?", (class_id,))
    if not cls or cls["teacher_id"] != session["user_id"]:
        flash("Not authorized", "danger")
        return redirect(url_for("dashboard"))

    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected", "warning")
        return redirect(url_for("class_detail", class_id=class_id))

    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        folder = class_folder(class_id)
        filename_on_disk = f"{class_id}_{uuid.uuid4().hex}_{filename}"
        file.save(os.path.join(folder, filename_on_disk))
        flash(f"File '{filename}' uploaded successfully.", "success")
    else:
        flash("File type not allowed.", "danger")

    return redirect(url_for("class_detail", class_id=class_id))

@app.route("/uploads/class_<int:class_id>/<filename>")
def serve_class_file(class_id, filename):
    return send_from_directory(class_folder(class_id), filename, as_attachment=True)

# ----------------------
# QUIZ GENERATION
# ----------------------
@app.route("/class/<int:class_id>/generate_quiz", methods=["POST"])
def generate_quiz_class(class_id):
    if "user_id" not in session:
        return jsonify({"error": "User not logged in"}), 401

    topic = request.json.get("topic", "").strip()
    if not topic:
        return jsonify({"error": "Topic cannot be empty"}), 400

    member = query_one(
        "SELECT * FROM class_members WHERE class_id = ? AND student_id = ?",
        (class_id, session["user_id"])
    )
    if not member:
        return jsonify({"error": "You are not a member of this class."}), 403

    folder_path = class_folder(class_id)
    class_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if allowed_file(f)]
    if not class_files:
        return jsonify({"error": "No files uploaded for this class."}), 400

    full_text = ""
    for path in class_files:
        try:
            if path.lower().endswith(".pdf"):
                with open(path, "rb") as f:
                    reader = PdfReader(f)
                    for page in reader.pages:
                        text = page.extract_text()
                        if text:
                            full_text += text + "\n"
            elif path.lower().endswith(".txt"):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    full_text += f.read() + "\n"
        except Exception as e:
            print(f"Failed to read {path}: {e}")

    if not full_text.strip():
        return jsonify({"error": "Uploaded files are empty or unreadable."}), 400

    system_prompt = (
        f"Using the following course materials, provide practice questions for students that want to practice for the exam. "
        f"Return your answer as plain text — no JSON parsing required.\n\n{full_text}"
    )
    prompt = "Generate the quiz question as plain text."

    try:
        ai_response = call_gemini_api(prompt, system_prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------------------
# ASSIGNMENTS
# ----------------------
@app.route("/class/<int:class_id>/create_assignment", methods=["GET", "POST"])
def create_assignment(class_id):
    cls = query_one("SELECT * FROM classes WHERE id = ?", (class_id,))
    if not cls or cls["teacher_id"] != session.get("user_id"):
        flash("Not authorized", "danger")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form.get("description", "").strip()
        points = int(request.form.get("points") or 100)
        db = get_db()
        db.execute("INSERT INTO assignments (class_id, title, description, points) VALUES (?, ?, ?, ?)",
                   (class_id, title, description, points))
        db.commit()
        flash("Assignment created", "success")
        return redirect(url_for("class_detail", class_id=class_id))
    return render_template("create_assignment.html", cls=cls)

@app.route("/assignment/<int:assignment_id>/submit", methods=["GET", "POST"])
def submit_assignment(assignment_id):
    assignment = query_one("SELECT * FROM assignments WHERE id = ?", (assignment_id,))
    if not assignment:
        flash("Assignment not found", "danger")
        return redirect(url_for("dashboard"))

    member = query_one("SELECT * FROM class_members WHERE class_id = ? AND student_id = ?",
                       (assignment["class_id"], session.get("user_id")))
    if not member:
        flash("You are not in this class", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        text = request.form.get("text", "").strip()
        file = request.files.get("file")
        filename_on_disk = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename_on_disk = f"{assignment['class_id']}_{uuid.uuid4().hex}_{filename}"
            file.save(os.path.join(class_folder(assignment["class_id"]), filename_on_disk))

        db = get_db()
        db.execute("""
            INSERT INTO submissions (assignment_id, student_id, filename, text)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(assignment_id, student_id) DO UPDATE SET
                filename=excluded.filename, text=excluded.text, submitted_at=CURRENT_TIMESTAMP, grade=NULL, feedback=NULL
        """, (assignment_id, session["user_id"], filename_on_disk, text))
        db.commit()
        flash("Submitted — good luck!", "success")
        return redirect(url_for("class_detail", class_id=assignment["class_id"]))

    return render_template("submit_assignment.html", assignment=assignment)

# ----------------------
# RUN
# ----------------------
if __name__ == "__main__":
    app.run(debug=True)
