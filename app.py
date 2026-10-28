import os
import io
import base64
import sqlite3
import secrets
import json
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps

import pyotp
import qrcode
from flask import (
    Flask, request, redirect, url_for, session, flash,
    render_template_string, jsonify, Response
)
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.secret_key = os.environ["APP_SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_PATH="/",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60)
)

bcrypt = Bcrypt(app)
oauth_client = OAuth(app)

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

google = None
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    google = oauth_client.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

DB_NAME = os.getenv("ONEKEY_DB_PATH", "onekey_university.db")

# Custom SAML and OAuth routes are educational simulations, not production IdP/OAuth implementations.
ENABLE_PROTOCOL_DEMOS = os.getenv("ENABLE_PROTOCOL_DEMOS", "false").lower() == "true"

@app.before_request
def restrict_educational_protocols():
    protected = ("/saml/", "/moodle/acs", "/moodle/login", "/oauth/", "/library/callback")
    if request.path.startswith(protected):
        if not ENABLE_PROTOCOL_DEMOS:
            return "Educational protocol simulation disabled. Set ENABLE_PROTOCOL_DEMOS=true for local study only.", 403
        if request.remote_addr not in ("127.0.0.1", "::1"):
            return "Educational protocol simulation is restricted to localhost.", 403


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def add_column_if_missing(conn, table, column, definition):
    cur = conn.execute(f"PRAGMA table_info({table})")
    cols = {row[1] for row in cur.fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

def init_db():
    conn = get_db()
    c = conn.cursor()

    # users
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password_hash TEXT,
        mfa_secret TEXT,
        auth_provider TEXT DEFAULT 'local',
        role TEXT DEFAULT 'student',
        created_at TEXT,
        last_login TEXT
    )""")
    add_column_if_missing(conn, "users", "role", "TEXT DEFAULT 'student'")
    add_column_if_missing(conn, "users", "last_login", "TEXT")

    # login_attempts
    c.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        identifier TEXT PRIMARY KEY,
        failed_count INTEGER DEFAULT 0,
        locked_until TEXT
    )""")

    # audit_logs
    c.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        username TEXT,
        event_type TEXT,
        app_name TEXT,
        protocol TEXT,
        status TEXT,
        details TEXT
    )""")

    # saml_log
    c.execute("""CREATE TABLE IF NOT EXISTS saml_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        direction TEXT,
        packet_type TEXT,
        raw_b64 TEXT,
        decoded_xml TEXT,
        remote_addr TEXT,
        captured_at TEXT
    )""")

    # authorization_codes
    c.execute("""CREATE TABLE IF NOT EXISTS authorization_codes (
        code TEXT PRIMARY KEY,
        username TEXT,
        client_id TEXT,
        redirect_uri TEXT,
        expires_at TEXT
    )""")

    # oauth_events
    c.execute("""CREATE TABLE IF NOT EXISTS oauth_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event_type TEXT,
        client_id TEXT,
        username TEXT,
        status TEXT,
        details TEXT
    )""")

    # courses
    c.execute("""CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT,
        name TEXT,
        instructor TEXT,
        credits INTEGER,
        description TEXT,
        schedule TEXT
    )""")

    # enrollments
    c.execute("""CREATE TABLE IF NOT EXISTS enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        course_id INTEGER,
        progress INTEGER DEFAULT 0,
        enrolled_at TEXT
    )""")

    # assignments
    c.execute("""CREATE TABLE IF NOT EXISTS assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER,
        title TEXT,
        description TEXT,
        due_date TEXT,
        max_score INTEGER DEFAULT 100
    )""")

    # submissions
    c.execute("""CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assignment_id INTEGER,
        username TEXT,
        content TEXT,
        submitted_at TEXT,
        score INTEGER,
        status TEXT DEFAULT 'Submitted'
    )""")

    # announcements
    c.execute("""CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER,
        title TEXT,
        content TEXT,
        posted_at TEXT
    )""")

    # grades
    c.execute("""CREATE TABLE IF NOT EXISTS grades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        course_id INTEGER,
        quiz_score REAL DEFAULT 0,
        assignment_score REAL DEFAULT 0,
        midterm_score REAL DEFAULT 0,
        final_score REAL DEFAULT 0
    )""")

    # library_books
    c.execute("""CREATE TABLE IF NOT EXISTS library_books (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        author TEXT,
        isbn TEXT,
        category TEXT,
        description TEXT,
        available INTEGER DEFAULT 1
    )""")

    # borrowed_books
    c.execute("""CREATE TABLE IF NOT EXISTS borrowed_books (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        book_id INTEGER,
        username TEXT,
        borrowed_at TEXT,
        due_date TEXT,
        returned_at TEXT
    )""")

    # registration_courses
    c.execute("""CREATE TABLE IF NOT EXISTS registration_courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT,
        name TEXT,
        credits INTEGER,
        instructor TEXT,
        schedule TEXT,
        seats_total INTEGER,
        seats_available INTEGER
    )""")

    # student_registrations
    c.execute("""CREATE TABLE IF NOT EXISTS student_registrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        course_id INTEGER,
        registered_at TEXT,
        UNIQUE(username, course_id)
    )""")

    # advising_notes
    c.execute("""CREATE TABLE IF NOT EXISTS advising_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        advisor_username TEXT,
        student_username TEXT,
        note TEXT,
        created_at TEXT
    )""")

    # course_materials
    c.execute("""CREATE TABLE IF NOT EXISTS course_materials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER,
        title TEXT,
        material_type TEXT,
        week INTEGER,
        description TEXT
    )""")

    # Add schedule columns to registration_courses if missing
    add_column_if_missing(conn, "registration_courses", "days", "TEXT DEFAULT ''")
    add_column_if_missing(conn, "registration_courses", "start_time", "TEXT DEFAULT ''")
    add_column_if_missing(conn, "registration_courses", "end_time", "TEXT DEFAULT ''")
    add_column_if_missing(conn, "registration_courses", "room", "TEXT DEFAULT ''")

    conn.commit()
    _seed_data(conn)
    conn.close()

def _seed_data(conn):
    c = conn.cursor()

    # Admin user
    c.execute("SELECT id FROM users WHERE username='admin'")
    if not c.fetchone():
        ph = bcrypt.generate_password_hash(os.environ["DEMO_ADMIN_PASSWORD"]).decode()
        sec = pyotp.random_base32()
        c.execute("""INSERT INTO users (username,email,password_hash,mfa_secret,auth_provider,role,created_at)
            VALUES (?,?,?,?,?,?,?)""",
            ("admin","admin@ju.edu.jo",ph,sec,"local","admin",datetime.utcnow().isoformat()))

    # Demo student
    c.execute("SELECT id FROM users WHERE username='student1'")
    if not c.fetchone():
        ph = bcrypt.generate_password_hash(os.environ["DEMO_STUDENT_PASSWORD"]).decode()
        sec = pyotp.random_base32()
        c.execute("""INSERT INTO users (username,email,password_hash,mfa_secret,auth_provider,role,created_at)
            VALUES (?,?,?,?,?,?,?)""",
            ("student1","student1@ju.edu.jo",ph,sec,"local","student",datetime.utcnow().isoformat()))

    # Faculty user
    c.execute("SELECT id FROM users WHERE username='faculty1'")
    if not c.fetchone():
        ph = bcrypt.generate_password_hash(os.environ["DEMO_FACULTY_PASSWORD"]).decode()
        sec = pyotp.random_base32()
        c.execute("""INSERT INTO users (username,email,password_hash,mfa_secret,auth_provider,role,created_at)
            VALUES (?,?,?,?,?,?,?)""",
            ("faculty1","faculty1@ju.edu.jo",ph,sec,"local","faculty",datetime.utcnow().isoformat()))

    # Courses
    c.execute("SELECT COUNT(*) FROM courses")
    if c.fetchone()[0] == 0:
        courses = [
            ("1911371","Authentication & Security Models","Dr. Oraib AbuAlganam",3,
             "Covers authentication protocols, access control models, cryptographic techniques, and SSO systems.","Sun/Tue 10:00–11:30"),
            ("1910511","Network Security","Dr. Saleh Al-Sharaeh",3,
             "Network threats, firewalls, VPNs, intrusion detection systems, and security architectures.","Mon/Wed 08:00–09:30"),
            ("1910341","Database Systems","Dr. Ahmad Khamayseh",3,
             "Relational databases, SQL, normalization, transactions, and database security.","Sun/Tue 13:00–14:30"),
            ("1910221","Software Engineering","Dr. Lina Nashwan",3,
             "Software development lifecycle, requirements engineering, design patterns, and testing.","Mon/Wed 12:00–13:30"),
            ("1910451","Web Development","Dr. Mariam Issa",3,
             "HTML5, CSS3, JavaScript, REST APIs, and modern web frameworks.","Sun/Tue 15:00–16:30"),
        ]
        c.executemany("""INSERT INTO courses (code,name,instructor,credits,description,schedule)
            VALUES (?,?,?,?,?,?)""", courses)

    # Enroll student1 in courses 1-3
    c.execute("SELECT COUNT(*) FROM enrollments WHERE username='student1'")
    if c.fetchone()[0] == 0:
        for cid in [1, 2, 3]:
            c.execute("""INSERT INTO enrollments (username,course_id,progress,enrolled_at)
                VALUES (?,?,?,?)""",
                ("student1", cid, [68, 45, 82][cid-1], datetime.utcnow().isoformat()))

    # Assignments
    c.execute("SELECT COUNT(*) FROM assignments")
    if c.fetchone()[0] == 0:
        now = datetime.utcnow()
        assignments = [
            (1,"Lab Report: OAuth2 Flow","Implement and document a working OAuth2 authorization code flow.",(now+timedelta(days=3)).strftime("%Y-%m-%d"),100),
            (1,"SAML Implementation Report","Document the SAML SSO flow with XML examples.",(now+timedelta(days=10)).strftime("%Y-%m-%d"),100),
            (1,"MFA Analysis Paper","Analyze different MFA methods and their security implications.",(now-timedelta(days=5)).strftime("%Y-%m-%d"),100),
            (2,"Firewall Configuration Lab","Configure and test firewall rules on a simulated network.",(now+timedelta(days=7)).strftime("%Y-%m-%d"),100),
            (2,"VPN Setup Report","Document IPSec VPN configuration and key exchange.",(now+timedelta(days=14)).strftime("%Y-%m-%d"),100),
            (3,"Database Design Project","Design an ER diagram and normalize to 3NF.",(now-timedelta(days=2)).strftime("%Y-%m-%d"),100),
            (3,"SQL Query Optimization","Optimize 10 complex queries and explain the indexes used.",(now+timedelta(days=5)).strftime("%Y-%m-%d"),100),
        ]
        c.executemany("""INSERT INTO assignments (course_id,title,description,due_date,max_score)
            VALUES (?,?,?,?,?)""", assignments)

    # Grades
    c.execute("SELECT COUNT(*) FROM grades WHERE username='student1'")
    if c.fetchone()[0] == 0:
        grades = [
            ("student1",1,82,76,71,0),
            ("student1",2,65,70,0,0),
            ("student1",3,90,88,85,0),
        ]
        c.executemany("""INSERT INTO grades (username,course_id,quiz_score,assignment_score,midterm_score,final_score)
            VALUES (?,?,?,?,?,?)""", grades)

    # Announcements
    c.execute("SELECT COUNT(*) FROM announcements")
    if c.fetchone()[0] == 0:
        now = datetime.utcnow()
        anns = [
            (1,"Project Phase 2 Released","Phase 2 of the SSO project is now available. Deadline is 2 weeks from today. Read the requirements carefully.",(now-timedelta(days=1)).isoformat()),
            (1,"Midterm Results Posted","Midterm exam grades are now available in the grade portal. Class average: 74/100.",(now-timedelta(days=5)).isoformat()),
            (2,"Lab Session Rescheduled","This week's lab session has been moved to Wednesday at 10:00 AM in Room CS-204.",(now-timedelta(days=2)).isoformat()),
            (2,"Guest Lecture: Penetration Testing","Industry expert from CyberSecure will give a guest lecture on ethical hacking next Tuesday.",(now-timedelta(days=4)).isoformat()),
            (3,"Quiz 3 Next Week","Quiz 3 will cover transactions, concurrency control, and database recovery. Review chapters 15–18.",(now-timedelta(hours=12)).isoformat()),
        ]
        c.executemany("""INSERT INTO announcements (course_id,title,content,posted_at)
            VALUES (?,?,?,?)""", anns)

    # Library books
    c.execute("SELECT COUNT(*) FROM library_books")
    if c.fetchone()[0] == 0:
        books = [
            ("Computer Security: Art and Science","Matt Bishop","978-0201440997","Cybersecurity",
             "Comprehensive coverage of computer security principles, policies, and mechanisms.",1),
            ("Network Security Essentials","William Stallings","978-0135764268","Networking",
             "Applications and standards in network security including cryptography and key management.",1),
            ("Database System Concepts","Silberschatz, Korth, Sudarshan","978-0078022159","Databases",
             "The definitive textbook on database systems covering SQL, ER modeling, and storage.",1),
            ("Clean Code","Robert C. Martin","978-0132350884","Software Engineering",
             "A handbook of agile software craftsmanship for writing readable, maintainable code.",0),
            ("Artificial Intelligence: A Modern Approach","Russell & Norvig","978-0134610993","AI & ML",
             "The standard reference text on artificial intelligence covering all major approaches.",1),
            ("The Web Application Hacker's Handbook","Stuttard & Pinto","978-1118026472","Cybersecurity",
             "Finding and exploiting security flaws in web applications with practical techniques.",1),
            ("Introduction to Algorithms","Cormen et al.","978-0262046305","Computer Science",
             "Comprehensive coverage of algorithms including analysis, design, and data structures.",1),
            ("Applied Cryptography","Bruce Schneier","978-0471117094","Cybersecurity",
             "Protocols, algorithms, and source code in C for implementing cryptographic systems.",0),
            ("Software Engineering","Ian Sommerville","978-0133943030","Software Engineering",
             "Principles and best practices for professional software development at scale.",1),
            ("Hacking: The Art of Exploitation","Jon Erickson","978-1593271442","Cybersecurity",
             "Hands-on approach to programming, network communications, and hacking techniques.",1),
            ("Deep Learning","Goodfellow, Bengio, Courville","978-0262035613","AI & ML",
             "Comprehensive introduction to deep learning methods, theory, and applications.",1),
            ("Computer Networks","Andrew Tanenbaum","978-0132126953","Networking",
             "Classic reference on computer networks covering all layers of the protocol stack.",1),
        ]
        c.executemany("""INSERT INTO library_books (title,author,isbn,category,description,available)
            VALUES (?,?,?,?,?,?)""", books)

    # Registration courses
    c.execute("SELECT COUNT(*) FROM registration_courses")
    if c.fetchone()[0] == 0:
        reg_courses = [
            ("1911371","Authentication & Security Models",3,"Dr. Oraib AbuAlganam","Sun/Tue 10:00",35,12),
            ("1910511","Network Security",3,"Dr. Saleh Al-Sharaeh","Mon/Wed 08:00",30,5),
            ("1910341","Database Systems",3,"Dr. Ahmad Khamayseh","Sun/Tue 13:00",40,23),
            ("1910221","Software Engineering",3,"Dr. Lina Nashwan","Mon/Wed 12:00",35,18),
            ("1910451","Web Development",3,"Dr. Mariam Issa","Sun/Tue 15:00",30,9),
            ("1910231","Data Structures",3,"Dr. Khaled Shal","Mon/Wed 10:00",40,31),
            ("1910361","Operating Systems",3,"Dr. Randa Saleh","Sun/Tue 08:00",35,7),
            ("1910481","Computer Architecture",3,"Dr. Basem Obeidat","Thu 09:00",25,14),
            ("1910311","Discrete Mathematics",3,"Dr. Eman Bani-Ata","Mon/Wed 14:00",45,28),
            ("1910571","Machine Learning",3,"Dr. Nidal Almayoof","Sun/Tue 16:00",25,3),
        ]
        c.executemany("""INSERT INTO registration_courses (code,name,credits,instructor,schedule,seats_total,seats_available)
            VALUES (?,?,?,?,?,?,?)""", reg_courses)

    # Advising notes
    c.execute("SELECT COUNT(*) FROM advising_notes")
    if c.fetchone()[0] == 0:
        c.execute("""INSERT INTO advising_notes (advisor_username,student_username,note,created_at)
            VALUES (?,?,?,?)""",
            ("admin","student1","Student is performing well in security-related courses. Recommended enrolling in Advanced Cryptography next semester.",datetime.utcnow().isoformat()))

    # Course materials
    c.execute("SELECT COUNT(*) FROM course_materials")
    if c.fetchone()[0] == 0:
        materials = [
            (1,"Lecture 1: Introduction to Authentication","PDF",1,"Overview of authentication models and identity protocols."),
            (1,"Lecture 2: OAuth2 and OIDC Slides","Slides",2,"Detailed walkthrough of OAuth2 authorization code flow."),
            (1,"Lab Sheet: SAML Implementation","Lab",3,"Hands-on lab for implementing SAML SSO with XML examples."),
            (1,"Project Guidelines","PDF",4,"Complete project requirements and grading rubric."),
            (2,"Lecture 1: Network Threats Overview","PDF",1,"Types of network attacks, threat actors, and mitigation."),
            (2,"Lecture 2: Firewalls and IDS Slides","Slides",2,"Configuring firewalls, IDS/IPS, and network segmentation."),
            (2,"Lab Sheet: Firewall Configuration","Lab",3,"Step-by-step lab for configuring firewall rules."),
            (2,"Project Guidelines","PDF",4,"Network security project requirements and deliverables."),
            (3,"Lecture 1: Database Design","PDF",1,"Entity-relationship diagrams and normalization to 3NF."),
            (3,"Lecture 2: SQL and Transactions Slides","Slides",2,"Advanced SQL, transactions, and concurrency control."),
            (3,"Lab Sheet: Query Optimization","Lab",3,"Practical lab for SQL query optimization techniques."),
            (3,"Project Guidelines","PDF",4,"Database project requirements and grading criteria."),
        ]
        c.executemany("""INSERT INTO course_materials (course_id,title,material_type,week,description)
            VALUES (?,?,?,?,?)""", materials)

    # Update registration_courses with days/time/room if columns were just added
    c.execute("SELECT id, schedule FROM registration_courses WHERE days='' OR days IS NULL")
    rows = c.fetchall()
    schedule_map = {
        "Sun/Tue 10:00": ("Sun,Tue","10:00","11:30","CS-101"),
        "Mon/Wed 08:00": ("Mon,Wed","08:00","09:30","CS-202"),
        "Sun/Tue 13:00": ("Sun,Tue","13:00","14:30","CS-103"),
        "Mon/Wed 12:00": ("Mon,Wed","12:00","13:30","CS-204"),
        "Sun/Tue 15:00": ("Sun,Tue","15:00","16:30","CS-105"),
        "Mon/Wed 10:00": ("Mon,Wed","10:00","11:30","CS-206"),
        "Sun/Tue 08:00": ("Sun,Tue","08:00","09:30","CS-107"),
        "Thu 09:00":     ("Thu","09:00","10:30","CS-308"),
        "Mon/Wed 14:00": ("Mon,Wed","14:00","15:30","CS-209"),
        "Sun/Tue 16:00": ("Sun,Tue","16:00","17:30","CS-110"),
    }
    for row in rows:
        key = (row[1] or "").strip()
        if key in schedule_map:
            days, st, et, room = schedule_map[key]
            c.execute("UPDATE registration_courses SET days=?, start_time=?, end_time=?, room=? WHERE id=?",
                      (days, st, et, room, row[0]))

    conn.commit()

init_db()

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def log_event(username, event_type, app_name, protocol, status, details=""):
    try:
        conn = get_db()
        conn.execute("""INSERT INTO audit_logs (timestamp,username,event_type,app_name,protocol,status,details)
            VALUES (?,?,?,?,?,?,?)""",
            (datetime.utcnow().isoformat(), username or "anonymous", event_type, app_name, protocol, status, details))
        conn.commit()
        conn.close()
    except Exception:
        pass

def log_saml_packet(direction, packet_type, raw_b64, decoded_xml):
    try:
        conn = get_db()
        conn.execute("""INSERT INTO saml_log (direction,packet_type,raw_b64,decoded_xml,remote_addr,captured_at)
            VALUES (?,?,?,?,?,?)""",
            (direction, packet_type, raw_b64, decoded_xml, request.remote_addr, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    except Exception:
        pass

def log_oauth_event(event_type, client_id, username, status, details=""):
    try:
        conn = get_db()
        conn.execute("""INSERT INTO oauth_events (timestamp,event_type,client_id,username,status,details)
            VALUES (?,?,?,?,?,?)""",
            (datetime.utcnow().isoformat(), event_type, client_id, username, status, details))
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_current_user():
    if "user" not in session:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (session["user"],)).fetchone()
    conn.close()
    return dict(row) if row else None

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            session["next_url"] = request.path
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def check_lock(identifier):
    conn = get_db()
    row = conn.execute("SELECT failed_count, locked_until FROM login_attempts WHERE identifier=?", (identifier,)).fetchone()
    conn.close()
    if not row or not row["locked_until"]:
        return False
    return datetime.utcnow() < datetime.fromisoformat(row["locked_until"])

def record_failed(identifier):
    conn = get_db()
    row = conn.execute("SELECT failed_count FROM login_attempts WHERE identifier=?", (identifier,)).fetchone()
    if row:
        fc = row["failed_count"] + 1
        lu = (datetime.utcnow() + timedelta(minutes=5)).isoformat() if fc >= 5 else None
        conn.execute("UPDATE login_attempts SET failed_count=?, locked_until=? WHERE identifier=?", (fc, lu, identifier))
    else:
        conn.execute("INSERT INTO login_attempts (identifier,failed_count,locked_until) VALUES (?,?,?)", (identifier,1,None))
    conn.commit()
    conn.close()

def clear_failed(identifier):
    conn = get_db()
    conn.execute("DELETE FROM login_attempts WHERE identifier=?", (identifier,))
    conn.commit()
    conn.close()

def update_last_login(username):
    conn = get_db()
    conn.execute("UPDATE users SET last_login=? WHERE username=?", (datetime.utcnow().isoformat(), username))
    conn.commit()
    conn.close()

# ── CAPTCHA ───────────────────────────────────────────────────────────────────
import random as _random

def generate_captcha():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    code = "".join(_random.choice(alphabet) for _ in range(6))
    session["captcha_answer"] = code
    return code

# ── NOTIFICATIONS ─────────────────────────────────────────────────────────────
def get_notifications(username):
    notifs = []
    try:
        conn = get_db()
        now_str = datetime.utcnow().strftime("%Y-%m-%d")
        soon_str = (datetime.utcnow() + timedelta(days=3)).strftime("%Y-%m-%d")

        # E-Learning: assignments due soon
        rows = conn.execute("""
            SELECT a.title, a.due_date, c.name as cname FROM assignments a
            JOIN courses c ON a.course_id=c.id
            JOIN enrollments e ON e.course_id=a.course_id AND e.username=?
            WHERE a.due_date BETWEEN ? AND ?
            AND a.id NOT IN (SELECT assignment_id FROM submissions WHERE username=?)
        """, (username, now_str, soon_str, username)).fetchall()
        for r in rows:
            notifs.append({"title":"Assignment Due Soon","message":f"{r['title']} in {r['cname']} is due {r['due_date']}","type":"warning","source":"E-Learning","time":r['due_date']})

        # E-Learning: overdue assignments
        rows = conn.execute("""
            SELECT a.title, a.due_date, c.name as cname FROM assignments a
            JOIN courses c ON a.course_id=c.id
            JOIN enrollments e ON e.course_id=a.course_id AND e.username=?
            WHERE a.due_date < ?
            AND a.id NOT IN (SELECT assignment_id FROM submissions WHERE username=?)
        """, (username, now_str, username)).fetchall()
        for r in rows:
            notifs.append({"title":"Assignment Overdue","message":f"{r['title']} in {r['cname']} was due {r['due_date']}","type":"danger","source":"E-Learning","time":r['due_date']})

        # E-Learning: recent submissions (last 7 days)
        rows = conn.execute("""
            SELECT s.submitted_at, a.title FROM submissions s
            JOIN assignments a ON s.assignment_id=a.id
            WHERE s.username=? AND s.submitted_at >= datetime('now','-7 days')
        """, (username,)).fetchall()
        for r in rows:
            notifs.append({"title":"Assignment Submitted","message":f"Your submission for '{r['title']}' was received","type":"success","source":"E-Learning","time":r['submitted_at'][:10]})

        # E-Learning: new announcements (last 7 days)
        rows = conn.execute("""
            SELECT ann.title, ann.posted_at, c.name as cname FROM announcements ann
            JOIN courses c ON ann.course_id=c.id
            JOIN enrollments e ON e.course_id=ann.course_id AND e.username=?
            WHERE ann.posted_at >= datetime('now','-7 days')
        """, (username,)).fetchall()
        for r in rows:
            notifs.append({"title":"New Announcement","message":f"{r['title']} in {r['cname']}","type":"info","source":"E-Learning","time":r['posted_at'][:10]})

        # Library: books due soon (within 3 days)
        rows = conn.execute("""
            SELECT b.title, bb.due_date FROM borrowed_books bb
            JOIN library_books b ON bb.book_id=b.id
            WHERE bb.username=? AND bb.returned_at IS NULL
            AND bb.due_date BETWEEN ? AND ?
        """, (username, now_str, soon_str)).fetchall()
        for r in rows:
            notifs.append({"title":"Book Due Soon","message":f"'{r['title']}' is due back on {r['due_date'][:10]}","type":"warning","source":"Library","time":r['due_date'][:10]})

        # Library: overdue books
        rows = conn.execute("""
            SELECT b.title, bb.due_date FROM borrowed_books bb
            JOIN library_books b ON bb.book_id=b.id
            WHERE bb.username=? AND bb.returned_at IS NULL AND bb.due_date < ?
        """, (username, now_str)).fetchall()
        for r in rows:
            notifs.append({"title":"Book Overdue","message":f"'{r['title']}' was due {r['due_date'][:10]} — please return it","type":"danger","source":"Library","time":r['due_date'][:10]})

        # Registration: registered courses count
        reg_count = conn.execute("SELECT COUNT(*) FROM student_registrations WHERE username=?", (username,)).fetchone()[0]
        if reg_count > 0:
            total_credits = conn.execute("""SELECT COALESCE(SUM(rc.credits),0) FROM registration_courses rc
                JOIN student_registrations sr ON rc.id=sr.course_id WHERE sr.username=?""", (username,)).fetchone()[0]
            if total_credits >= 15:
                notifs.append({"title":"Credit Limit Warning","message":f"You have {total_credits}/18 credits registered. Approaching maximum.","type":"warning","source":"Registration","time":now_str})

        # Security: recent failed logins
        failed = conn.execute("""SELECT COUNT(*) FROM audit_logs WHERE username=? AND event_type='login_failed'
            AND timestamp >= datetime('now','-24 hours')""", (username,)).fetchone()[0]
        if failed > 0:
            notifs.append({"title":"Recent Failed Login","message":f"{failed} failed login attempt(s) in the last 24 hours","type":"danger","source":"Security","time":now_str})

        # Security: recent SAML login
        saml = conn.execute("""SELECT COUNT(*) FROM audit_logs WHERE username=? AND event_type='saml_response_accepted'
            AND timestamp >= datetime('now','-24 hours')""", (username,)).fetchone()[0]
        if saml > 0:
            notifs.append({"title":"Recent SAML Login","message":"You authenticated to E-Learning via SAML SSO recently","type":"info","source":"Security","time":now_str})

        # Security: recent OAuth2
        oauth2 = conn.execute("""SELECT COUNT(*) FROM audit_logs WHERE username=? AND event_type='oauth_callback_success'
            AND timestamp >= datetime('now','-24 hours')""", (username,)).fetchone()[0]
        if oauth2 > 0:
            notifs.append({"title":"Recent OAuth2 Authorization","message":"Digital Library was authorized via OAuth2 recently","type":"info","source":"Security","time":now_str})

        conn.close()
    except Exception:
        pass
    # Sort newest-feeling items first (danger > warning > info > success)
    order = {"danger":0,"warning":1,"info":2,"success":3}
    notifs.sort(key=lambda x: order.get(x["type"],4))
    return notifs

# ── SMS OTP ───────────────────────────────────────────────────────────────────
def generate_sms_otp():
    code = str(_random.randint(100000, 999999))
    session["faculty_sms_code"]    = code
    session["faculty_sms_expires"] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
    session["faculty_sms_verified"] = False
    return code

GOOGLE_SVG = """<svg width="18" height="18" viewBox="0 0 48 48" style="margin-right:8px;flex-shrink:0">
  <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
  <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
  <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24s.92 7.54 2.56 10.78l7.97-6.19z"/>
  <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
</svg>"""

# ══════════════════════════════════════════════════════════════════════════════
# BASE TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════

AUTH_CSS = """
:root {
  --emerald:   #10b981;
  --emerald-d: #047857;
  --emerald-l: #d1fae5;
  --emerald-s: #ecfdf5;
  --text:      #0f172a;
  --text2:     #334155;
  --muted:     #64748b;
  --border:    #e2e8f0;
  --bg:        #f8fafc;
  --card:      #ffffff;
  --shadow:    rgba(15,23,42,0.08);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
}
.auth-wrap {
  display: grid;
  grid-template-columns: 1fr 1fr;
  min-height: 100vh;
}
@media(max-width:768px){ .auth-wrap{grid-template-columns:1fr;} .auth-left{display:none;} }
.auth-left {
  background: linear-gradient(150deg, #ecfdf5 0%, #d1fae5 40%, #a7f3d0 100%);
  display: flex; flex-direction: column; justify-content: center; align-items: flex-start;
  padding: 60px 56px;
  position: relative; overflow: hidden;
}
.auth-left::before {
  content: '';
  position: absolute; top: -40%; left: -20%; width: 140%; height: 140%;
  background: radial-gradient(ellipse at 30% 40%, rgba(16,185,129,0.18) 0%, transparent 60%),
              radial-gradient(ellipse at 70% 70%, rgba(4,120,87,0.1) 0%, transparent 50%);
  pointer-events: none;
}
.auth-grid-bg {
  position: absolute; inset: 0;
  background-image: linear-gradient(rgba(16,185,129,0.08) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(16,185,129,0.08) 1px, transparent 1px);
  background-size: 40px 40px;
  pointer-events: none;
}
.brand-logo {
  display: flex; align-items: center; gap: 12px; margin-bottom: 48px;
}
.brand-icon {
  width: 48px; height: 48px; border-radius: 12px;
  background: linear-gradient(135deg, var(--emerald), var(--emerald-d));
  display: flex; align-items: center; justify-content: center;
  font-weight: 900; font-size: 22px; color: #fff;
  box-shadow: 0 4px 14px rgba(16,185,129,0.35);
}
.brand-name { font-size: 22px; font-weight: 700; color: var(--text); }
.brand-sub  { font-size: 12px; color: var(--muted); }
.auth-left h1 { font-size: 38px; font-weight: 800; color: var(--text); line-height: 1.2; margin-bottom: 16px; }
.auth-left h1 span { color: var(--emerald-d); }
.auth-tagline { font-size: 16px; color: var(--text2); margin-bottom: 48px; line-height: 1.6; }
.auth-features { display: flex; flex-direction: column; gap: 16px; }
.feat { display: flex; align-items: center; gap: 14px; }
.feat-icon {
  width: 40px; height: 40px; border-radius: 10px; flex-shrink: 0;
  background: rgba(16,185,129,0.15); border: 1px solid rgba(16,185,129,0.25);
  display: flex; align-items: center; justify-content: center; font-size: 18px;
}
.feat-text strong { display: block; font-size: 14px; color: var(--text); }
.feat-text span   { font-size: 12px; color: var(--text2); }

.auth-right {
  display: flex; align-items: center; justify-content: center;
  background: var(--bg); padding: 40px 24px;
}
.auth-card {
  width: 100%; max-width: 420px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 40px 36px;
  box-shadow: 0 8px 40px var(--shadow);
}
.auth-card h2 { font-size: 26px; font-weight: 800; color: var(--text); margin-bottom: 6px; }
.auth-card .sub { color: var(--muted); font-size: 14px; margin-bottom: 30px; }

.form-group { margin-bottom: 18px; }
.form-group label { display: block; font-size: 13px; font-weight: 600; color: var(--text2); margin-bottom: 6px; }
.form-group input {
  width: 100%; padding: 11px 14px; border-radius: 10px;
  background: #fff; border: 1px solid var(--border);
  color: var(--text); font-size: 14px; outline: none;
  transition: border-color 0.2s;
}
.form-group input:focus { border-color: var(--emerald); box-shadow: 0 0 0 3px rgba(16,185,129,0.12); }
.form-group input::placeholder { color: #94a3b8; }

.btn-primary-ok {
  display: block; width: 100%; padding: 12px;
  background: linear-gradient(135deg, var(--emerald) 0%, var(--emerald-d) 100%);
  color: #fff; font-weight: 700; font-size: 15px;
  border: none; border-radius: 10px; cursor: pointer;
  transition: opacity 0.2s, transform 0.15s;
  box-shadow: 0 4px 14px rgba(16,185,129,0.3);
}
.btn-primary-ok:hover { opacity: 0.9; transform: translateY(-1px); }

.google-btn-ok {
  display: flex; align-items: center; justify-content: center;
  width: 100%; padding: 11px; margin-top: 12px;
  background: #fff; border: 1px solid var(--border);
  border-radius: 10px; color: var(--text); font-weight: 600; font-size: 14px;
  text-decoration: none; cursor: pointer;
  transition: background 0.2s, border-color 0.2s, box-shadow 0.2s;
}
.google-btn-ok:hover { background: #f8fafc; border-color: #cbd5e1; box-shadow: 0 2px 8px var(--shadow); color: var(--text); }

.divider { display: flex; align-items: center; gap: 12px; margin: 16px 0; }
.divider::before, .divider::after { content:''; flex: 1; height: 1px; background: var(--border); }
.divider span { color: var(--muted); font-size: 12px; }

.auth-link { text-align: center; margin-top: 20px; font-size: 13px; color: var(--muted); }
.auth-link a { color: var(--emerald-d); text-decoration: none; font-weight: 600; }

.flash-msg { padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 13px; }
.flash-danger  { background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c; }
.flash-success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }
.flash-info    { background: #f0f9ff; border: 1px solid #bae6fd; color: #0369a1; }
"""

DASH_CSS = """
:root {
  --bg:        #f8fafc;
  --bg2:       #f1f5f9;
  --sidebar:   #ffffff;
  --emerald:   #10b981;
  --emerald-d: #047857;
  --emerald-l: #d1fae5;
  --emerald-s: #ecfdf5;
  --cyan:      #06b6d4;
  --text:      #0f172a;
  --text2:     #334155;
  --muted:     #64748b;
  --border:    #e2e8f0;
  --card:      #ffffff;
  --hover:     #f8fafc;
  --shadow:    rgba(15,23,42,0.07);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  display: flex;
}
/* Sidebar */
.sidebar {
  width: 240px; min-height: 100vh; flex-shrink: 0;
  background: var(--sidebar);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column;
  position: sticky; top: 0; height: 100vh; overflow-y: auto;
}
.sidebar-brand {
  padding: 24px 20px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px;
}
.brand-icon {
  width: 36px; height: 36px; border-radius: 9px;
  background: linear-gradient(135deg, var(--emerald), var(--emerald-d));
  display: flex; align-items: center; justify-content: center;
  font-weight: 900; font-size: 16px; color: #fff; flex-shrink: 0;
  box-shadow: 0 2px 8px rgba(16,185,129,0.3);
}
.brand-text { font-size: 13px; font-weight: 700; color: var(--text); line-height: 1.3; }
.brand-text small { color: var(--muted); font-weight: 400; font-size: 11px; display: block; }
.nav-section { padding: 20px 12px 8px; }
.nav-section-label { font-size: 10px; font-weight: 700; color: #94a3b8; letter-spacing: 1px; text-transform: uppercase; padding: 0 8px; margin-bottom: 6px; }
.nav-link-ok {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 10px; border-radius: 8px; margin-bottom: 2px;
  color: var(--muted); font-size: 13px; font-weight: 500;
  text-decoration: none; cursor: pointer;
  transition: background 0.15s, color 0.15s;
  border: none; background: none; width: 100%; text-align: left;
}
.nav-link-ok:hover { background: var(--emerald-s); color: var(--emerald-d); }
.nav-link-ok.active { background: var(--emerald-l); color: var(--emerald-d); font-weight: 600; }
.nav-icon { width: 18px; height: 18px; opacity: 0.7; flex-shrink: 0; }
.nav-link-ok.active .nav-icon { opacity: 1; }
.sidebar-foot {
  margin-top: auto; padding: 16px 12px; border-top: 1px solid var(--border);
}
/* Main */
.main-wrap { flex: 1; display: flex; flex-direction: column; min-height: 100vh; overflow: hidden; }
.topbar {
  height: 60px; flex-shrink: 0;
  background: #ffffff;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; padding: 0 28px;
  gap: 16px; position: sticky; top: 0; z-index: 100;
  box-shadow: 0 1px 4px var(--shadow);
}
.topbar-title { font-size: 15px; font-weight: 600; color: var(--text); flex: 1; }
.topbar-title small { font-size: 12px; color: var(--muted); font-weight: 400; display: block; }
.badge-ok {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;
}
.badge-success { background: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }
.badge-info    { background: #f0f9ff; color: #0369a1; border: 1px solid #bae6fd; }
.badge-warn    { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }
.badge-danger  { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }
.badge-muted   { background: #f8fafc; color: var(--muted); border: 1px solid var(--border); }
.badge-saml    { background: #faf5ff; color: #6d28d9; border: 1px solid #ddd6fe; }
.badge-oauth   { background: #fff7ed; color: #9a3412; border: 1px solid #fed7aa; }
.badge-cyan    { background: #f0f9ff; color: #0369a1; border: 1px solid #bae6fd; }
.user-avatar {
  width: 36px; height: 36px; border-radius: 50%; flex-shrink: 0;
  background: linear-gradient(135deg, var(--emerald), var(--emerald-d));
  display: flex; align-items: center; justify-content: center;
  font-weight: 700; font-size: 14px; color: #fff;
}
.page-body { flex: 1; padding: 28px; overflow-y: auto; }
/* Cards */
.card-ok {
  background: var(--card); border: 1px solid var(--border); border-radius: 14px;
  box-shadow: 0 2px 8px var(--shadow);
}
.card-ok-pad { padding: 22px; }
.app-card-ok {
  background: var(--card); border: 1px solid var(--border); border-radius: 14px;
  padding: 22px; height: 100%; transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s;
  text-decoration: none; color: inherit; display: block;
  box-shadow: 0 2px 8px var(--shadow);
}
.app-card-ok:hover {
  transform: translateY(-3px);
  border-color: rgba(16,185,129,0.35);
  box-shadow: 0 8px 24px rgba(16,185,129,0.12);
  color: inherit;
}
.app-icon-ok {
  width: 46px; height: 46px; border-radius: 12px; margin-bottom: 14px;
  display: flex; align-items: center; justify-content: center; font-size: 22px;
}
.icon-emerald { background: #ecfdf5; border: 1px solid #a7f3d0; }
.icon-cyan    { background: #ecfeff; border: 1px solid #a5f3fc; }
.icon-purple  { background: #f5f3ff; border: 1px solid #ddd6fe; }
.icon-orange  { background: #fff7ed; border: 1px solid #fed7aa; }
.icon-blue    { background: #eff6ff; border: 1px solid #bfdbfe; }
.icon-red     { background: #fef2f2; border: 1px solid #fecaca; }
.card-title { font-size: 15px; font-weight: 700; color: var(--text); margin-bottom: 6px; }
.card-desc  { font-size: 12px; color: var(--muted); line-height: 1.6; margin-bottom: 14px; }
/* Stats */
.stat-card {
  background: var(--card); border: 1px solid var(--border); border-radius: 14px;
  padding: 20px 22px;
  box-shadow: 0 2px 8px var(--shadow);
}
.stat-value { font-size: 32px; font-weight: 800; color: var(--text); }
.stat-label { font-size: 12px; color: var(--muted); margin-top: 4px; }
.stat-icon  { font-size: 28px; opacity: 0.7; }
/* Table */
.table-wrap { overflow-x: auto; }
table.ok-table { width: 100%; border-collapse: collapse; font-size: 13px; }
table.ok-table thead th {
  background: var(--bg2); color: var(--muted);
  font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase;
  padding: 10px 14px; border-bottom: 1px solid var(--border); text-align: left;
}
table.ok-table tbody td {
  padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; color: var(--text);
}
table.ok-table tbody tr:last-child td { border-bottom: none; }
table.ok-table tbody tr:hover { background: var(--hover); }
/* Buttons */
.btn-ok {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 600;
  border: none; cursor: pointer; transition: opacity 0.15s, transform 0.1s;
  text-decoration: none;
}
.btn-ok:hover { opacity: 0.85; transform: translateY(-1px); }
.btn-emerald { background: var(--emerald-s); color: var(--emerald-d); border: 1px solid var(--emerald-l); }
.btn-emerald-solid { background: var(--emerald); color: #fff; box-shadow: 0 2px 8px rgba(16,185,129,0.3); }
.btn-cyan    { background: #ecfeff; color: #0e7490; border: 1px solid #a5f3fc; }
.btn-danger  { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }
.btn-muted   { background: #f8fafc; color: var(--muted); border: 1px solid var(--border); }
.btn-sm-ok { padding: 5px 12px; font-size: 12px; }
/* Progress */
.progress-ok { height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
.progress-fill { height: 100%; border-radius: 3px; background: linear-gradient(90deg, var(--emerald), var(--emerald-d)); }
/* Timeline */
.timeline-item { display: flex; gap: 14px; padding: 12px 0; border-bottom: 1px solid var(--border); }
.timeline-item:last-child { border-bottom: none; }
.tl-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; margin-top: 5px; }
.tl-content .tl-title { font-size: 13px; color: var(--text); }
.tl-content .tl-time  { font-size: 11px; color: var(--muted); margin-top: 2px; }
/* Flash */
.flash-msg { padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 13px; }
.flash-danger  { background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c; }
.flash-success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }
.flash-info    { background: #f0f9ff; border: 1px solid #bae6fd; color: #0369a1; }
/* Misc */
.section-title { font-size: 18px; font-weight: 700; color: var(--text); margin-bottom: 4px; }
.section-sub   { font-size: 13px; color: var(--muted); margin-bottom: 22px; }
.row-ok { display: grid; gap: 16px; }
.row-2 { grid-template-columns: repeat(2, 1fr); }
.row-3 { grid-template-columns: repeat(3, 1fr); }
.row-4 { grid-template-columns: repeat(4, 1fr); }
.row-6 { grid-template-columns: repeat(6, 1fr); }
@media(max-width:1100px){ .row-4{grid-template-columns:repeat(2,1fr);} .row-6{grid-template-columns:repeat(3,1fr);} }
@media(max-width:768px) { .row-2,.row-3,.row-4,.row-6{grid-template-columns:1fr;} .sidebar{display:none;} }
.text-em { color: var(--emerald-d); }
.text-cy { color: var(--cyan); }
.text-mu { color: var(--muted); }
hr-ok { border: none; border-top: 1px solid var(--border); margin: 20px 0; }
.form-ok { display: flex; flex-direction: column; gap: 14px; }
.form-ok label { font-size: 12px; font-weight: 600; color: var(--text2); margin-bottom: 4px; display: block; }
.form-ok input, .form-ok textarea, .form-ok select {
  width: 100%; padding: 9px 12px; border-radius: 8px;
  background: #fff; border: 1px solid var(--border);
  color: var(--text); font-size: 13px; outline: none;
}
.form-ok input:focus, .form-ok textarea:focus, .form-ok select:focus { border-color: var(--emerald); box-shadow: 0 0 0 3px rgba(16,185,129,0.1); }
.filter-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 16px; }
.filter-row select {
  padding: 7px 10px; border-radius: 8px;
  background: #fff; border: 1px solid var(--border);
  color: var(--text); font-size: 12px; cursor: pointer;
}
.filter-row input {
  padding: 7px 12px; border-radius: 8px;
  background: #fff; border: 1px solid var(--border);
  color: var(--text); font-size: 12px; outline: none; min-width: 200px;
}
.saml-xml { background: #f8fafc; border: 1px solid var(--border); border-radius: 8px;
  padding: 14px; font-size: 11px; font-family: monospace; overflow-x: auto;
  white-space: pre-wrap; color: #0369a1; max-height: 300px; overflow-y: auto; }
.security-item { display: flex; justify-content: space-between; align-items: center;
  padding: 14px 0; border-bottom: 1px solid var(--border); }
.security-item:last-child { border-bottom: none; }
.security-label { font-size: 13px; color: var(--muted); }
.security-value { font-size: 13px; color: var(--text); font-weight: 600; }
"""

def build_sidebar(active):
    nav_items = [
        ("dashboard","Dashboard","M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"),
        ("elearning","E-Learning","M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"),
        ("library","Digital Library","M8 14v3m4-3v3m4-3v3M3 21h18M3 10h18M3 7l9-4 9 4M4 10h16v11H4z"),
        ("registration","Registration","M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"),
        ("faculty","Faculty Portal","M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"),
        ("security","Account Security","M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"),
        ("audit","Audit Center","M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"),
    ]
    html = ""
    for key, label, path_d in nav_items:
        cls = "nav-link-ok active" if active == key else "nav-link-ok"
        href = {"dashboard": "/dashboard", "elearning": "/moodle", "library": "/library",
                "registration": "/registration", "faculty": "/faculty",
                "security": "/security", "audit": "/audit"}[key]
        html += f"""<a href="{href}" class="{cls}">
            <svg class="nav-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8">
                <path stroke-linecap="round" stroke-linejoin="round" d="{path_d}"/>
            </svg>{label}</a>"""
    return html

def render_dash(content, active="dashboard", page_title="Dashboard"):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    initials = (user.get("username","?")[0]).upper()
    role_badge = {"admin":"badge-danger","faculty":"badge-info","student":"badge-muted"}.get(user.get("role","student"),"badge-muted")
    provider = user.get("auth_provider","local")
    provider_label = "Google OAuth" if provider == "google" else "Local + MFA"
    flashes = ""
    for cat, msg in session.pop("_flashes", []) if hasattr(session, "pop") else []:
        flashes += f'<div class="flash-msg flash-{cat}">{msg}</div>'
    # Also grab real flashes
    from flask import get_flashed_messages
    for cat, msg in get_flashed_messages(with_categories=True):
        flashes += f'<div class="flash-msg flash-{cat}">{msg}</div>'

    # Notification bell count
    try:
        notifs = get_notifications(user["username"])
        notif_count = len(notifs)
    except Exception:
        notif_count = 0
    notif_badge = f'<span style="position:absolute;top:-4px;right:-4px;background:#ef4444;color:#fff;font-size:10px;font-weight:700;border-radius:10px;padding:1px 5px;line-height:1.4">{notif_count}</span>' if notif_count > 0 else ""
    notif_bell = f"""<a href="/notifications" title="Notifications" style="position:relative;display:inline-flex;align-items:center;justify-content:center;width:36px;height:36px;border-radius:50%;background:#f1f5f9;border:1px solid #e2e8f0;color:#64748b;text-decoration:none;transition:color 0.2s,border-color 0.2s" onmouseover="this.style.color='#0f172a';this.style.borderColor='#cbd5e1'" onmouseout="this.style.color='#64748b';this.style.borderColor='#e2e8f0'">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 16a2 2 0 0 0 2-2H6a2 2 0 0 0 2 2zm.995-14.901a1 1 0 1 0-1.99 0A5.002 5.002 0 0 0 3 6c0 1.098-.5 6-2 7h14c-1.5-1-2-5.902-2-7 0-2.42-1.72-4.44-4.005-4.901z"/></svg>
      {notif_badge}
    </a>"""

    return render_template_string(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><title>{page_title} — OneKey</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>{DASH_CSS}</style>
</head>
<body>
<nav class="sidebar">
  <div class="sidebar-brand">
    <div class="brand-icon">OK</div>
    <div class="brand-text">OneKey<small>University Portal</small></div>
  </div>
  <div class="nav-section">
    <div class="nav-section-label">Navigation</div>
    {build_sidebar(active)}
  </div>
  <div class="sidebar-foot">
    <a href="/logout" class="nav-link-ok" style="color:#f87171">
      <svg class="nav-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8">
        <path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
      </svg>Sign Out</a>
  </div>
</nav>
<div class="main-wrap">
  <header class="topbar">
    <div class="topbar-title">
      {page_title}
      <small>University of Jordan — SSO Platform</small>
    </div>
    <span class="badge-ok badge-success">HTTPS Secure</span>
    <span class="badge-ok {role_badge}">{user.get('role','student').title()}</span>
    <span class="badge-ok badge-muted">{provider_label}</span>
    {notif_bell}
    <div class="user-avatar">{initials}</div>
  </header>
  <div class="page-body">
    {flashes}
    {content}
  </div>
</div>
</body>
</html>""")

# ══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════

def auth_page(content, title="Sign In"):
    from flask import get_flashed_messages
    flashes = ""
    for cat, msg in get_flashed_messages(with_categories=True):
        flashes += f'<div class="flash-msg flash-{cat}">{msg}</div>'
    return render_template_string(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><title>{title} — OneKey</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>{AUTH_CSS}</style>
</head>
<body>
<div class="auth-wrap">
  <div class="auth-left">
    <div class="auth-grid-bg"></div>
    <div class="brand-logo">
      <div class="brand-icon">OK</div>
      <div>
        <div style="font-weight:700;color:#0f172a;font-size:16px">OneKey</div>
        <div style="font-size:11px;color:var(--muted)">University Portal</div>
      </div>
    </div>
    <h1>Secure <span>University</span> Access</h1>
    <p class="auth-tagline">Sign in once. Access all your university services securely with enterprise-grade authentication.</p>
    <div class="auth-features">
      <div class="feat"><div class="feat-icon"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="#10b981" viewBox="0 0 16 16"><path d="M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2z"/></svg></div><div class="feat-text"><strong>Single Sign-On</strong><span>One identity across all university apps</span></div></div>
      <div class="feat"><div class="feat-icon"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="#10b981" viewBox="0 0 16 16"><path d="M11 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h6zM5 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2H5z"/><path d="M8 14a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"/></svg></div><div class="feat-text"><strong>Multi-Factor Authentication</strong><span>TOTP-based MFA with Google Authenticator</span></div></div>
      <div class="feat"><div class="feat-icon"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="#10b981" viewBox="0 0 16 16"><path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.725 10.725 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.615.615 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524z"/></svg></div><div class="feat-text"><strong>HTTPS Protected</strong><span>All traffic encrypted with TLS</span></div></div>
      <div class="feat"><div class="feat-icon"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="#10b981" viewBox="0 0 16 16"><path d="M3 2h10a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1zm9 1H4v10h8V3z"/><path d="M5 5.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5zm0 2a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5zm0 2a.5.5 0 0 1 .5-.5h2a.5.5 0 0 1 0 1h-2a.5.5 0 0 1-.5-.5z"/></svg></div><div class="feat-text"><strong>Security Audit Logs</strong><span>Full event logging for compliance</span></div></div>
    </div>
  </div>
  <div class="auth-right">
    <div class="auth-card">
      {flashes}
      {content}
    </div>
  </div>
</div>
</body>
</html>""")

@app.route("/")
def home():
    return redirect(url_for("dashboard") if "user" in session else url_for("login"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        email    = request.form.get("email","").strip()
        password = request.form.get("password","")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("register"))
        ph  = bcrypt.generate_password_hash(password).decode()
        sec = pyotp.random_base32()
        try:
            conn = get_db()
            conn.execute("""INSERT INTO users (username,email,password_hash,mfa_secret,auth_provider,role,created_at)
                VALUES (?,?,?,?,?,?,?)""", (username,email,ph,sec,"local","student",datetime.utcnow().isoformat()))
            conn.commit()
            conn.close()
            log_event(username,"user_registered","OneKey","Local","Success","New local account created")
            totp = pyotp.TOTP(sec)
            uri  = totp.provisioning_uri(name=email, issuer_name="OneKey University Portal")
            img  = qrcode.make(uri)
            buf  = io.BytesIO(); img.save(buf,"PNG")
            qr64 = base64.b64encode(buf.getvalue()).decode()
            content = f"""
            <h2>Authenticator Setup</h2>
            <p class="sub">Scan this QR code with Google Authenticator.</p>
            <div style="text-align:center;margin:20px 0">
              <img src="data:image/png;base64,{qr64}" style="width:180px;border-radius:8px">
            </div>
            <div style="background:rgba(255,255,255,0.05);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:20px">
              <div style="font-size:11px;color:var(--muted);margin-bottom:4px">Manual setup key</div>
              <div style="font-family:monospace;color:var(--emerald);font-size:14px;word-break:break-all">{sec}</div>
            </div>
            <a href="/login" class="btn-primary-ok" style="display:block;text-align:center;text-decoration:none">Continue to Sign In</a>"""
            return auth_page(content, "MFA Setup")
        except Exception:
            flash("This username is already registered.", "danger")
            return redirect(url_for("register"))
    content = """
    <h2>Create Account</h2>
    <p class="sub">Register for university portal access</p>
    <form method="POST" class="form-ok" style="display:block">
      <div class="form-group"><label>University ID</label><input name="username" placeholder="e.g. 0221885" required></div>
      <div class="form-group"><label>Email Address</label><input type="email" name="email" placeholder="student@ju.edu.jo" required></div>
      <div class="form-group"><label>Password</label><input type="password" name="password" placeholder="Minimum 8 characters" required></div>
      <button type="submit" class="btn-primary-ok">Create Account</button>
    </form>
    <div class="auth-link">Already registered? <a href="/login">Sign in</a></div>"""
    return auth_page(content, "Create Account")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username   = request.form.get("username","").strip()
        password   = request.form.get("password","")
        captcha_in = request.form.get("captcha","").strip()
        identifier = username or request.remote_addr

        # CAPTCHA check first
        expected = str(session.get("captcha_answer", "")).strip().upper()
        captcha_ok = bool(expected) and captcha_in.strip().upper() == expected

        if not captcha_ok:
            log_event(username,"captcha_failed","OneKey","CAPTCHA","Failed","Wrong CAPTCHA answer")
            flash("Verification code is incorrect. Please try again.", "danger")
            captcha_q = generate_captcha()
            return _login_page(captcha_q)

        log_event(username,"captcha_passed","OneKey","CAPTCHA","Success","CAPTCHA answered correctly")

        if check_lock(identifier):
            log_event(username,"login_blocked","OneKey","Local","Failed","Account temporarily locked")
            flash("Too many failed attempts. Account locked for 5 minutes.", "danger")
            captcha_q = generate_captcha()
            return _login_page(captcha_q)
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=? OR email=?", (username,username)).fetchone()
        conn.close()
        if user and user["auth_provider"] == "local" and bcrypt.check_password_hash(user["password_hash"], password):
            clear_failed(identifier)
            session["temp_user"]   = user["username"]
            session["temp_email"]  = user["email"]
            session["temp_role"]   = user["role"]
            log_event(user["username"],"login_password_ok","OneKey","Local","Success","Password verified, MFA required")
            return redirect(url_for("mfa_verify"))
        if user and user["auth_provider"] != "local":
            flash("This account uses Google sign-in.", "info")
            captcha_q = generate_captcha()
            return _login_page(captcha_q)
        record_failed(identifier)
        log_event(username,"login_failed","OneKey","Local","Failed","Invalid credentials")
        flash("Invalid username or password.", "danger")

    captcha_q = generate_captcha()
    return _login_page(captcha_q)

def _login_page(captcha_q):
    from flask import get_flashed_messages
    flashes = ""
    for cat, msg in get_flashed_messages(with_categories=True):
        flashes += f'<div class="flash-msg flash-{cat}">{msg}</div>'
    content = f"""
    <h2>Welcome Back</h2>
    <p class="sub">Sign in to your university account</p>
    {flashes}
    <form method="POST" style="margin-bottom:0">
      <div class="form-group"><label>University ID or Email</label><input name="username" placeholder="username or email" required></div>
      <div class="form-group"><label>Password</label><input type="password" name="password" placeholder="Your password" required></div>
      <div class="form-group">
  <label style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="#047857" viewBox="0 0 16 16">
      <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.725 10.725 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.615.615 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524z"/>
    </svg>
    OneKey Verify
  </label>

  <div style="
    background:
      repeating-linear-gradient(135deg, rgba(16,185,129,0.10) 0px, rgba(16,185,129,0.10) 2px, transparent 2px, transparent 8px),
      radial-gradient(circle at 20% 30%, rgba(4,120,87,0.16) 0 1px, transparent 2px),
      radial-gradient(circle at 70% 60%, rgba(6,182,212,0.14) 0 1px, transparent 2px),
      #ecfdf5;
    border: 1px solid #a7f3d0;
    border-radius: 12px;
    padding: 14px;
    margin-bottom: 10px;
    text-align: center;
  ">
    <div style="font-size:11px;color:#64748b;margin-bottom:8px">
      Enter the verification code shown below
    </div>
    <div style="
      font-family: Consolas, monospace;
      font-size: 24px;
      font-weight: 800;
      letter-spacing: 9px;
      color: #047857;
      text-shadow: 1px 1px 0 rgba(255,255,255,0.8);
      user-select: none;
    ">{captcha_q}</div>
  </div>

  <input name="captcha" placeholder="Enter verification code" maxlength="6" required autocomplete="off"
    style="font-size:16px;text-align:center;font-family:monospace;letter-spacing:4px;text-transform:uppercase">

  <div style="margin-top:8px;text-align:right">
    <a href="/login" style="font-size:12px;color:#047857;text-decoration:none;font-weight:600">
      Refresh code
    </a>
  </div>
</div>
      <button type="submit" class="btn-primary-ok">Sign In</button>
    </form>
    <div class="divider"><span>or</span></div>
    <a href="/google/login" class="google-btn-ok">{GOOGLE_SVG}Continue with Google</a>
    <div class="auth-link" style="margin-top:16px">New student? <a href="/register">Create account</a></div>"""
    return render_template_string(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><title>Sign In — OneKey</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>{AUTH_CSS}</style>
</head>
<body>
<div class="auth-wrap">
  <div class="auth-left">
    <div class="auth-grid-bg"></div>
    <div class="brand-logo">
      <div class="brand-icon">OK</div>
      <div>
        <div style="font-weight:700;color:#0f172a;font-size:16px">OneKey</div>
        <div style="font-size:11px;color:var(--muted)">University Portal</div>
      </div>
    </div>
    <h1>Secure <span>University</span> Access</h1>
    <p class="auth-tagline">Sign in once. Access all your university services securely with enterprise-grade authentication.</p>
    <div class="auth-features">
      <div class="feat"><div class="feat-icon" style="font-size:16px"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="#10b981" viewBox="0 0 16 16"><path d="M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2z"/></svg></div><div class="feat-text"><strong>Single Sign-On</strong><span>One identity across all university apps</span></div></div>
      <div class="feat"><div class="feat-icon" style="font-size:16px"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="#10b981" viewBox="0 0 16 16"><path d="M1 2.828c.885-.37 2.154-.769 3.388-.893 1.33-.134 2.458.063 3.112.752v9.746c-.935-.53-2.12-.603-3.213-.493-1.18.12-2.37.461-3.287.811V2.828zm7.5-.141c.654-.689 1.782-.886 3.112-.752 1.234.124 2.503.523 3.388.893v9.923c-.918-.35-2.107-.692-3.287-.81-1.094-.111-2.278-.039-3.213.492V2.687zM8 1.783C7.015.936 5.587.81 4.287.94c-1.514.153-3.042.672-3.994 1.105A.5.5 0 0 0 0 2.5v11a.5.5 0 0 0 .707.455c.882-.4 2.303-.881 3.68-1.02 1.409-.142 2.59.087 3.223.877a.5.5 0 0 0 .78 0c.633-.79 1.814-1.019 3.222-.877 1.378.139 2.8.62 3.681 1.02A.5.5 0 0 0 16 13.5v-11a.5.5 0 0 0-.293-.455c-.952-.433-2.48-.952-3.994-1.105C10.413.809 8.985.936 8 1.783z"/></svg></div><div class="feat-text"><strong>Multi-Factor Authentication</strong><span>TOTP-based MFA with Google Authenticator</span></div></div>
      <div class="feat"><div class="feat-icon" style="font-size:16px"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="#10b981" viewBox="0 0 16 16"><path d="M8 0c-.69 0-1.843.265-2.928.56-1.11.3-2.229.655-2.887.87a1.54 1.54 0 0 0-1.044 1.262c-.596 4.477.787 7.795 2.465 9.99a11.777 11.777 0 0 0 2.517 2.453c.386.273.744.482 1.048.625.28.132.581.24.883.24s.604-.108.883-.24a7.16 7.16 0 0 0 1.048-.625 11.775 11.775 0 0 0 2.517-2.453c1.678-2.195 3.061-5.513 2.465-9.99a1.541 1.541 0 0 0-1.044-1.263 62.467 62.467 0 0 0-2.887-.87C9.843.266 8.69 0 8 0zm2.146 5.146a.5.5 0 0 1 .708.708l-3 3a.5.5 0 0 1-.708 0l-1.5-1.5a.5.5 0 1 1 .708-.708L7.5 7.793l2.646-2.647z"/></svg></div><div class="feat-text"><strong>CAPTCHA Protection</strong><span>Math CAPTCHA prevents automated attacks</span></div></div>
      <div class="feat"><div class="feat-icon" style="font-size:16px"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="#10b981" viewBox="0 0 16 16"><path d="M3 14.5A1.5 1.5 0 0 1 1.5 13V3A1.5 1.5 0 0 1 3 1.5h8a.5.5 0 0 1 0 1H3a.5.5 0 0 0-.5.5v10a.5.5 0 0 0 .5.5h10a.5.5 0 0 0 .5-.5V8a.5.5 0 0 1 1 0v5a1.5 1.5 0 0 1-1.5 1.5H3z"/><path d="M8.354 10.354l7-7a.5.5 0 0 0-.708-.708L8 9.293 5.354 6.646a.5.5 0 1 0-.708.708l3 3a.5.5 0 0 0 .708 0z"/></svg></div><div class="feat-text"><strong>Security Audit Logs</strong><span>Full event logging for compliance</span></div></div>
    </div>
  </div>
  <div class="auth-right">
    <div class="auth-card">
      {content}
    </div>
  </div>
</div>
</body>
</html>""")

@app.route("/mfa_verify", methods=["GET","POST"])
def mfa_verify():
    if "temp_user" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("mfa_code","")
        conn = get_db()
        pending_user = conn.execute("SELECT mfa_secret FROM users WHERE username=?", (session["temp_user"],)).fetchone()
        conn.close()
        if not pending_user or not pending_user["mfa_secret"]:
            return redirect(url_for("login"))
        totp = pyotp.TOTP(pending_user["mfa_secret"])
        if totp.verify(code, valid_window=1):
            username = session.pop("temp_user")
            email    = session.pop("temp_email")
            role     = session.pop("temp_role", "student")
            session.permanent = True
            session["user"]    = username
            session["email"]   = email
            session["role"]    = role
            session["provider"]= "local"
            session["login_at"]= datetime.utcnow().isoformat()
            update_last_login(username)
            log_event(username,"mfa_verified","OneKey","MFA","Success","MFA verification passed")
            next_url   = session.pop("next_url", None)
            saml_next  = session.pop("saml_pending", None)
            safe_next = saml_next if saml_next and saml_next.startswith("/saml/") else (next_url if next_url and next_url.startswith("/") and not next_url.startswith("//") else None)
            return redirect(safe_next or url_for("dashboard"))
        log_event(session.get("temp_user","?"),"mfa_failed","OneKey","MFA","Failed","Invalid TOTP code")
        flash("Invalid verification code.", "danger")
    content = """
    <h2>Verification Required</h2>
    <p class="sub">Enter the 6-digit code from Google Authenticator</p>
    <form method="POST">
      <div class="form-group">
        <label>Authentication Code</label>
        <input name="mfa_code" maxlength="6" placeholder="000000" style="text-align:center;font-size:22px;letter-spacing:8px;font-family:monospace" required autofocus>
      </div>
      <button type="submit" class="btn-primary-ok">Verify Identity</button>
    </form>
    <div class="auth-link"><a href="/login">Back to sign in</a></div>"""
    return auth_page(content, "MFA Verification")

@app.route("/google/login")
def google_login():
    if not google:
        flash("Google sign-in is not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env.", "info")
        return redirect(url_for("login"))
    log_event("anonymous","google_oauth_start","OneKey","Google OAuth","Success","OAuth2 flow initiated")
    redirect_uri = url_for("google_callback", _external=True, _scheme="https")
    return google.authorize_redirect(redirect_uri)

@app.route("/google/callback")
def google_callback():
    if not google:
        flash("Google sign-in is not configured.", "danger")
        return redirect(url_for("login"))
    try:
        token     = google.authorize_access_token()
        user_info = google.get("https://openidconnect.googleapis.com/v1/userinfo").json()
        email = user_info.get("email")
        name  = user_info.get("name", email)
        if not email:
            flash("Google sign-in failed: no email returned.", "danger")
            return redirect(url_for("login"))
        conn = get_db()
        row  = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            uname = email.split("@")[0]
            base  = uname; i = 1
            while conn.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone():
                uname = f"{base}{i}"; i += 1
            conn.execute("""INSERT INTO users (username,email,password_hash,mfa_secret,auth_provider,role,created_at)
                VALUES (?,?,?,?,?,?,?)""", (uname,email,"","","google","student",datetime.utcnow().isoformat()))
            conn.commit()
            username = uname
            role = "student"
        else:
            username = row["username"]
            role = row["role"]
        update_last_login(username)
        conn.close()
        session.permanent = True
        session["user"]    = username
        session["email"]   = email
        session["role"]    = role
        session["provider"]= "google"
        session["login_at"]= datetime.utcnow().isoformat()
        log_event(username,"google_oauth_success","OneKey","Google OAuth","Success",f"Authenticated via Google as {email}")
        saml_next = session.pop("saml_pending", None)
        return redirect(saml_next if saml_next and saml_next.startswith("/saml/") else url_for("dashboard"))
    except Exception as e:
        log_event("anonymous","google_oauth_failed","OneKey","Google OAuth","Failed",str(e))
        flash("Google sign-in failed. Please try again.", "danger")
        return redirect(url_for("login"))

@app.route("/logout")
def logout():
    username = session.get("user","anonymous")
    log_event(username,"logout","OneKey","Local","Success","User signed out")
    session.clear()
    return redirect(url_for("login"))

# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    conn = get_db()
    enroll_count = conn.execute("SELECT COUNT(*) FROM enrollments WHERE username=?", (user["username"],)).fetchone()[0]
    borrowed     = conn.execute("SELECT COUNT(*) FROM borrowed_books WHERE username=? AND returned_at IS NULL", (user["username"],)).fetchone()[0]
    reg_count    = conn.execute("SELECT COUNT(*) FROM student_registrations WHERE username=?", (user["username"],)).fetchone()[0]
    sec_events   = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE username=? AND status='Failed'", (user["username"],)).fetchone()[0]
    recent_logs  = conn.execute("SELECT * FROM audit_logs WHERE username=? ORDER BY id DESC LIMIT 8", (user["username"],)).fetchall()
    conn.close()
    login_at = session.get("login_at","")
    if login_at:
        try: login_at = datetime.fromisoformat(login_at).strftime("%b %d, %Y %H:%M UTC")
        except: pass
    last_login = user.get("last_login","")
    if last_login:
        try: last_login = datetime.fromisoformat(last_login).strftime("%b %d, %Y %H:%M UTC")
        except: pass

    tl_dots = {"Success":"#10b981","Failed":"#ef4444","Info":"#06b6d4"}
    tl_html = ""
    for log in recent_logs:
        dot_c = tl_dots.get(log["status"],"#94a3b8")
        ts = log["timestamp"][:16].replace("T"," ") if log["timestamp"] else ""
        tl_html += f"""<div class="timeline-item">
            <div class="tl-dot" style="background:{dot_c}"></div>
            <div class="tl-content">
              <div class="tl-title">{log['event_type']} — <span style="color:var(--muted)">{log['app_name']}</span></div>
              <div class="tl-time">{ts} &nbsp;·&nbsp; {log['protocol']} &nbsp;·&nbsp;
                <span style="color:{'#10b981' if log['status']=='Success' else '#ef4444'}">{log['status']}</span>
              </div>
            </div>
          </div>"""

    # Notification summary for dashboard
    try:
        dash_notifs = get_notifications(user["username"])
        notif_count = len(dash_notifs)
        danger_count  = sum(1 for n in dash_notifs if n["type"]=="danger")
        warning_count = sum(1 for n in dash_notifs if n["type"]=="warning")
    except Exception:
        dash_notifs = []; notif_count = 0; danger_count = 0; warning_count = 0

    # Show up to 4 most important notifications on dashboard
    preview_notifs = dash_notifs[:4]
    notif_preview_html = ""
    type_dot = {"danger":"#ef4444","warning":"#fbbf24","success":"#10b981","info":"#06b6d4"}
    for n in preview_notifs:
        dot_c = type_dot.get(n["type"],"#94a3b8")
        notif_preview_html += f"""<div style="display:flex;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
          <div style="width:7px;height:7px;border-radius:50%;background:{dot_c};margin-top:5px;flex-shrink:0"></div>
          <div>
            <div style="font-size:12px;font-weight:600;color:var(--text)">{n['title']}</div>
            <div style="font-size:11px;color:var(--muted)">{n['message'][:60]}{'...' if len(n['message'])>60 else ''}</div>
          </div>
        </div>"""
    if not notif_preview_html:
        notif_preview_html = '<div style="font-size:12px;color:var(--muted);padding:12px 0;text-align:center">No alerts at this time.</div>'

    # App cards — no emojis, use inline SVG icons
    def _app_icon(path_d, color):
        return f'<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" fill="none" stroke="{color}" stroke-width="1.6" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="{path_d}"/></svg>'

    app_cards_data = [
        ("/moodle","icon-emerald","E-Learning","Courses, assignments, announcements, and grades.","SAML SSO","badge-saml",
         "M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253","#10b981"),
        ("/library","icon-cyan","Digital Library","Books, journals, and borrowing management.","OAuth 2.0","badge-oauth",
         "M8 14v3m4-3v3m4-3v3M3 21h18M3 10h18M3 7l9-4 9 4M4 10h16v11H4z","#06b6d4"),
        ("/registration","icon-purple","Student Registration","Semester courses, schedule, and credits.","SSO","badge-success",
         "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4","#c084fc"),
        ("/faculty","icon-orange","Faculty Portal","Teaching schedules and academic tools.","Role-Based","badge-info",
         "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z","#fb923c"),
        ("/security","icon-blue","Account Security","MFA, CAPTCHA, sessions, and login activity.","Security","badge-success",
         "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z","#3b82f6"),
        ("/audit","icon-red","Audit Center","CAPTCHA, SMS OTP, SAML, OAuth2, MFA event logs.","Audit","badge-warn",
         "M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z","#ef4444"),
    ]
    cards_html = ""
    for href,icon_cls,title,desc,proto,proto_cls,path_d,color in app_cards_data:
        cards_html += f"""<a href="{href}" class="app-card-ok">
          <div class="app-icon-ok {icon_cls}" style="margin-bottom:14px">{_app_icon(path_d,color)}</div>
          <div class="card-title">{title}</div>
          <div class="card-desc">{desc}</div>
          <span class="badge-ok {proto_cls}">{proto}</span>
        </a>"""

    content = f"""
    <div style="margin-bottom:24px">
      <h1 class="section-title">Welcome, {user['username'].title()}</h1>
      <p class="section-sub">University of Jordan — Secure Portal &nbsp;·&nbsp; Session started {login_at}</p>
    </div>
    <div class="row-ok row-4" style="margin-bottom:24px">
      <div class="stat-card"><div style="display:flex;justify-content:space-between"><div><div class="stat-value text-em">{enroll_count}</div><div class="stat-label">Active Courses</div></div><div class="stat-icon" style="opacity:0.4"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" stroke="currentColor" stroke-width="1.6" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg></div></div></div>
      <div class="stat-card"><div style="display:flex;justify-content:space-between"><div><div class="stat-value text-cy">{borrowed}</div><div class="stat-label">Borrowed Books</div></div><div class="stat-icon" style="opacity:0.4"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" stroke="currentColor" stroke-width="1.6" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M8 14v3m4-3v3m4-3v3M3 21h18M3 10h18M3 7l9-4 9 4M4 10h16v11H4z"/></svg></div></div></div>
      <div class="stat-card"><div style="display:flex;justify-content:space-between"><div><div class="stat-value" style="color:#c084fc">{reg_count}</div><div class="stat-label">Registered Courses</div></div><div class="stat-icon" style="opacity:0.4"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" stroke="currentColor" stroke-width="1.6" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg></div></div></div>
      <div class="stat-card"><div style="display:flex;justify-content:space-between"><div><div class="stat-value" style="color:{'#ef4444' if sec_events>0 else '#10b981'}">{sec_events}</div><div class="stat-label">Security Events</div></div><div class="stat-icon" style="opacity:0.4"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" stroke="currentColor" stroke-width="1.6" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg></div></div></div>
    </div>
    <div class="row-ok row-3" style="margin-bottom:24px">
      <div style="grid-column:span 2">
        <div class="section-title" style="font-size:15px;margin-bottom:14px">University Applications</div>
        <div class="row-ok row-3">{cards_html}</div>
      </div>
      <div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="section-title" style="font-size:15px">My Alerts</div>
          <a href="/notifications" style="font-size:11px;color:var(--emerald);text-decoration:none">View all ({notif_count})</a>
        </div>
        <div class="card-ok card-ok-pad" style="margin-bottom:14px">
          {"<div style='display:flex;gap:8px;margin-bottom:10px'><span class=\"badge-ok badge-danger\" style=\"font-size:10px\">" + str(danger_count) + " Critical</span><span class=\"badge-ok badge-warn\" style=\"font-size:10px\">" + str(warning_count) + " Warnings</span></div>" if notif_count > 0 else ""}
          {notif_preview_html}
          {"<div style='margin-top:10px'><a href='/notifications' class='btn-ok btn-muted btn-sm-ok' style='font-size:11px'>View All Notifications</a></div>" if notif_count > 4 else ""}
        </div>
        <div class="section-title" style="font-size:15px;margin-bottom:14px">Recent Activity</div>
        <div class="card-ok card-ok-pad">
          {tl_html or '<p class="text-mu" style="font-size:13px">No activity yet.</p>'}
        </div>
        <div class="card-ok card-ok-pad" style="margin-top:14px">
          <div class="section-title" style="font-size:13px;margin-bottom:12px">Session Info</div>
          <div class="security-item" style="padding:8px 0"><span class="security-label">Account</span><span class="security-value">{user['username']}</span></div>
          <div class="security-item" style="padding:8px 0"><span class="security-label">Role</span><span class="security-value">{user['role'].title()}</span></div>
          <div class="security-item" style="padding:8px 0"><span class="security-label">Last Login</span><span class="security-value" style="font-size:11px">{last_login or 'Now'}</span></div>
          <div class="security-item" style="padding:8px 0;border-bottom:none"><span class="security-label">Status</span><span class="badge-ok badge-success">Active</span></div>
        </div>
      </div>
    </div>"""
    return render_dash(content, "dashboard", "Dashboard")

# ── NOTIFICATIONS CENTER ───────────────────────────────────────────────────────

@app.route("/notifications")
@login_required
def notifications():
    username = session["user"]
    notifs = get_notifications(username)
    log_event(username,"notifications_viewed","OneKey","App","Success","Notification center accessed")

    type_icon = {
        "danger":  '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="#f87171" viewBox="0 0 16 16"><path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/></svg>',
        "warning": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="#fbbf24" viewBox="0 0 16 16"><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm.93-9.412-1 4.705c-.07.34.029.533.304.533.194 0 .487-.07.686-.246l-.088.416c-.287.346-.92.598-1.465.598-.703 0-1.002-.422-.808-1.319l.738-3.468c.064-.293.006-.399-.287-.47l-.451-.081.082-.381 2.29-.287zM8 5.5a1 1 0 1 1 0-2 1 1 0 0 1 0 2z"/></svg>',
        "success": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="#10b981" viewBox="0 0 16 16"><path d="M2.5 8a5.5 5.5 0 0 1 8.25-4.764.5.5 0 0 0 .5-.866A6.5 6.5 0 1 0 14.5 8a.5.5 0 0 0-1 0 5.5 5.5 0 1 1-11 0z"/><path d="M15.354 3.354a.5.5 0 0 0-.708-.708L8 9.293 5.354 6.646a.5.5 0 1 0-.708.708l3 3a.5.5 0 0 0 .708 0l7-7z"/></svg>',
        "info":    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="#06b6d4" viewBox="0 0 16 16"><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm.93-9.412-1 4.705c-.07.34.029.533.304.533.194 0 .487-.07.686-.246l-.088.416c-.287.346-.92.598-1.465.598-.703 0-1.002-.422-.808-1.319l.738-3.468c.064-.293.006-.399-.287-.47l-.451-.081.082-.381 2.29-.287zM8 5.5a1 1 0 1 1 0-2 1 1 0 0 1 0 2z"/></svg>',
    }
    type_border = {"danger":"rgba(239,68,68,0.2)","warning":"rgba(251,191,36,0.2)","success":"rgba(16,185,129,0.2)","info":"rgba(6,182,212,0.2)"}
    source_badge = {"E-Learning":"badge-saml","Library":"badge-oauth","Registration":"badge-success","Security":"badge-danger"}

    notif_items = ""
    for n in notifs:
        icon = type_icon.get(n["type"], type_icon["info"])
        bdr  = type_border.get(n["type"], "rgba(255,255,255,0.08)")
        sbadge = source_badge.get(n["source"], "badge-muted")
        notif_items += f"""<div style="display:flex;gap:14px;padding:16px;border-bottom:1px solid var(--border);border-left:3px solid {bdr}">
          <div style="flex-shrink:0;padding-top:2px">{icon}</div>
          <div style="flex:1">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:4px">
              <div style="font-size:13px;font-weight:600;color:var(--text)">{n['title']}</div>
              <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;margin-left:12px">
                <span class="badge-ok {sbadge}" style="font-size:10px">{n['source']}</span>
                <span style="font-size:11px;color:var(--muted)">{n['time']}</span>
              </div>
            </div>
            <div style="font-size:12px;color:var(--muted)">{n['message']}</div>
          </div>
        </div>"""

    empty_state = ""
    if not notifs:
        empty_state = """<div style="text-align:center;padding:60px 20px;color:var(--muted)">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 16 16" style="opacity:0.3;margin-bottom:16px"><path d="M8 16a2 2 0 0 0 2-2H6a2 2 0 0 0 2 2zm.995-14.901a1 1 0 1 0-1.99 0A5.002 5.002 0 0 0 3 6c0 1.098-.5 6-2 7h14c-1.5-1-2-5.902-2-7 0-2.42-1.72-4.44-4.005-4.901z"/></svg>
          <div style="font-size:14px;font-weight:600;margin-bottom:8px">No notifications</div>
          <div style="font-size:12px">You are all caught up. No alerts at this time.</div>
        </div>"""

    # Summary counts by type
    counts = {"danger":0,"warning":0,"info":0,"success":0}
    for n in notifs: counts[n["type"]] = counts.get(n["type"],0) + 1

    content = f"""
    <div style="margin-bottom:22px;display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
      <div>
        <div class="section-title">Notifications</div>
        <div class="section-sub">Your alerts and updates from all university services</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <span class="badge-ok badge-danger"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" fill="currentColor" viewBox="0 0 16 16" style="margin-right:3px"><path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566z"/></svg>{counts['danger']} Critical</span>
        <span class="badge-ok badge-warn"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" fill="currentColor" viewBox="0 0 16 16" style="margin-right:3px"><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/></svg>{counts['warning']} Warnings</span>
        <span class="badge-ok badge-info">{counts['info']} Info</span>
        <span class="badge-ok badge-success">{counts['success']} Success</span>
      </div>
    </div>
    <div class="card-ok" style="margin-bottom:20px;overflow:hidden">
      {notif_items or empty_state}
    </div>
    <div style="font-size:11px;color:var(--muted);text-align:center">Notifications are generated dynamically from your activity across E-Learning, Library, Registration, and Security.</div>"""
    return render_dash(content, "dashboard", "Notifications")

# ══════════════════════════════════════════════════════════════════════════════
# E-LEARNING (SAML)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/moodle")
@login_required
def moodle():
    if "moodle_user" in session:
        return redirect(url_for("moodle_home"))
    content = """
    <div style="max-width:560px;margin:60px auto;text-align:center">
      <div class="app-icon-ok icon-emerald" style="width:64px;height:64px;margin:0 auto 20px;display:flex;align-items:center;justify-content:center">
        <svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="none" stroke="#10b981" stroke-width="1.6" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg>
      </div>
      <h2 class="section-title" style="margin-bottom:8px">E-Learning Platform</h2>
      <p class="section-sub" style="margin-bottom:28px">Secure access via SAML Single Sign-On. Your OneKey identity will be used to authenticate you with the E-Learning system.</p>
      <div class="card-ok card-ok-pad" style="text-align:left;margin-bottom:20px">
        <div style="font-size:12px;color:var(--muted);margin-bottom:10px;font-weight:700;letter-spacing:0.5px">SAML SSO FLOW</div>
        <div style="display:flex;flex-direction:column;gap:8px;font-size:12px;color:var(--muted)">
          <div><span class="badge-ok badge-saml" style="margin-right:8px">1</span> E-Learning sends AuthnRequest to OneKey IdP</div>
          <div><span class="badge-ok badge-saml" style="margin-right:8px">2</span> OneKey verifies your session</div>
          <div><span class="badge-ok badge-saml" style="margin-right:8px">3</span> OneKey returns signed SAMLResponse with your identity</div>
          <div><span class="badge-ok badge-saml" style="margin-right:8px">4</span> E-Learning grants you access</div>
        </div>
      </div>
      <a href="/moodle/login" class="btn-ok btn-emerald-solid" style="font-size:15px;padding:12px 32px">Sign In with OneKey SSO</a>
    </div>"""
    return render_dash(content, "elearning", "E-Learning")

@app.route("/moodle/login")
@login_required
def moodle_login():
    req_id = f"_moodle_{secrets.token_hex(8)}"
    raw_xml = f"""<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="{req_id}"
    Version="2.0"
    IssueInstant="{datetime.utcnow().isoformat()}Z"
    Destination="https://localhost:5050/saml/sso"
    AssertionConsumerServiceURL="https://localhost:5050/moodle/acs"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Moodle-Elearning</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"""
    saml_req = base64.urlsafe_b64encode(raw_xml.encode()).decode()
    log_saml_packet("SP→IdP", "AuthnRequest", saml_req, raw_xml)
    log_event(session["user"],"saml_authn_request","E-Learning","SAML","Success","AuthnRequest generated and sent to IdP")
    return redirect(url_for("saml_sso", SAMLRequest=saml_req, RelayState="moodle-home"))

@app.route("/saml/metadata")
def saml_metadata():
    xml = """<?xml version="1.0"?>
<EntityDescriptor entityID="OneKey-University-IdP"
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://localhost:5050/saml/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://localhost:5050/saml/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"""
    return Response(xml, mimetype="application/xml")

@app.route("/saml/sso")
def saml_sso():
    relay_state  = request.args.get("RelayState","")
    saml_request = request.args.get("SAMLRequest","")
    if saml_request:
        try: decoded = base64.urlsafe_b64decode(saml_request.encode()).decode()
        except: decoded = "(decode error)"
        log_saml_packet("IdP←SP (received)", "AuthnRequest", saml_request, decoded)
    if "user" not in session:
        session["saml_pending"] = request.full_path
        return redirect(url_for("login"))
    name_id   = session.get("email", session.get("user"))
    username  = session.get("user")
    role      = session.get("role","student")
    resp_id   = f"_resp_{secrets.token_hex(8)}"
    assert_id = f"_assert_{secrets.token_hex(8)}"
    now_iso   = datetime.utcnow().isoformat()
    response_xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{resp_id}" Version="2.0"
    IssueInstant="{now_iso}Z"
    Destination="https://localhost:5050/moodle/acs">
  <saml:Issuer>OneKey-University-IdP</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="{assert_id}" Version="2.0" IssueInstant="{now_iso}Z">
    <saml:Issuer>OneKey-University-IdP</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{(datetime.utcnow()+timedelta(minutes=5)).isoformat()}Z"
            Recipient="https://localhost:5050/moodle/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{now_iso}Z" NotOnOrAfter="{(datetime.utcnow()+timedelta(minutes=5)).isoformat()}Z">
      <saml:AudienceRestriction><saml:Audience>Moodle-Elearning</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="username"><saml:AttributeValue>{username}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="email"><saml:AttributeValue>{name_id}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="role"><saml:AttributeValue>{role}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="institution"><saml:AttributeValue>University of Jordan</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""
    saml_resp = base64.urlsafe_b64encode(response_xml.encode()).decode()
    log_saml_packet("IdP→SP", "SAMLResponse+Assertion", saml_resp, response_xml)
    log_event(username,"saml_response_issued","E-Learning","SAML","Success","SAMLResponse with Assertion sent to SP")
    return render_template_string(f"""<!DOCTYPE html>
<html><head><title>Redirecting...</title></head>
<body onload="document.forms[0].submit()" style="background:#f8fafc;color:#0f172a;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh">
<div style="text-align:center">
  <p style="color:#64748b;margin-bottom:20px">Completing SAML authentication...</p>
  <form method="POST" action="/moodle/acs">
    <input type="hidden" name="SAMLResponse" value="{saml_resp}">
    <input type="hidden" name="RelayState"   value="{relay_state}">
    <noscript><button type="submit">Continue</button></noscript>
  </form>
</div>
</body></html>""")

@app.route("/moodle/acs", methods=["POST"])
def moodle_acs():
    saml_resp = request.form.get("SAMLResponse","")
    try: decoded = base64.urlsafe_b64decode(saml_resp.encode()).decode()
    except: return "Invalid SAMLResponse", 400
    log_saml_packet("SP←IdP (ACS received)", "SAMLResponse+Assertion", saml_resp, decoded)
    log_event(session.get("user","?"),"saml_acs_received","E-Learning","SAML","Success","SAMLResponse accepted at ACS endpoint")
    session["moodle_user"] = session.get("user")
    return redirect(url_for("moodle_home"))

@app.route("/moodle/home")
@login_required
def moodle_home():
    if "moodle_user" not in session:
        return redirect(url_for("moodle"))
    username = session["user"]
    conn = get_db()
    enrollments = conn.execute("""
        SELECT c.*, e.progress, e.id as enroll_id FROM courses c
        JOIN enrollments e ON c.id = e.course_id
        WHERE e.username=?""", (username,)).fetchall()

    # Auto-enroll new users in demo courses if they have no enrollments
    if not enrollments:
        now_iso = datetime.utcnow().isoformat()
        for cid, prog in [(1, 20), (2, 10), (3, 35)]:
            existing = conn.execute("SELECT id FROM enrollments WHERE username=? AND course_id=?", (username, cid)).fetchone()
            if not existing:
                conn.execute("INSERT INTO enrollments (username,course_id,progress,enrolled_at) VALUES (?,?,?,?)",
                             (username, cid, prog, now_iso))
        conn.commit()
        enrollments = conn.execute("""
            SELECT c.*, e.progress, e.id as enroll_id FROM courses c
            JOIN enrollments e ON c.id = e.course_id
            WHERE e.username=?""", (username,)).fetchall()

    conn.close()
    log_event(username,"app_accessed","E-Learning","SAML","Success","E-Learning home page accessed")

    if not enrollments:
        courses_html = """<div class="card-ok card-ok-pad" style="text-align:center;padding:40px 20px">
          <div style="font-size:12px;color:var(--muted);margin-bottom:12px">No enrollments found.</div>
          <a href="/registration" class="btn-ok btn-emerald btn-sm-ok">Register for Courses</a>
        </div>"""
    else:
        courses_html = '<div class="row-ok row-3">'
        status_colors = {(0,40):"#f87171",(40,70):"#fbbf24",(70,101):"#10b981"}
        for e in enrollments:
            prog = e["progress"]
            sc = next((c for r,c in status_colors.items() if r[0]<=prog<r[1]),"#10b981")
            status_lbl = "Completed" if prog>=90 else ("In Progress" if prog>=20 else "Just Started")
            conn2 = get_db()
            next_assign = conn2.execute("""SELECT title, due_date FROM assignments WHERE course_id=? AND due_date >= date('now') ORDER BY due_date LIMIT 1""", (e["id"],)).fetchone()
            sub_count   = conn2.execute("""SELECT COUNT(*) FROM submissions WHERE username=? AND assignment_id IN (SELECT id FROM assignments WHERE course_id=?)""", (username, e["id"])).fetchone()[0]
            total_assign = conn2.execute("SELECT COUNT(*) FROM assignments WHERE course_id=?", (e["id"],)).fetchone()[0]
            conn2.close()
            next_html = f'<div style="font-size:11px;color:var(--muted);margin-top:6px"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" fill="currentColor" viewBox="0 0 16 16" style="margin-right:3px"><path d="M8 3.5a.5.5 0 0 0-1 0V9a.5.5 0 0 0 .252.434l3.5 2a.5.5 0 0 0 .496-.868L8 8.71V3.5z"/><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm7-8A7 7 0 1 1 1 8a7 7 0 0 1 14 0z"/></svg>Next: {next_assign["title"]} — {next_assign["due_date"]}</div>' if next_assign else '<div style="font-size:11px;color:var(--muted);margin-top:6px">No upcoming assignments</div>'
            courses_html += f"""<div class="card-ok card-ok-pad">
              <div style="display:flex;justify-content:space-between;margin-bottom:10px">
                <span class="badge-ok badge-muted" style="font-size:10px">{e['code']}</span>
                <span class="badge-ok" style="background:rgba(255,255,255,0.05);color:{sc};border:1px solid {sc}40;font-size:10px">{status_lbl}</span>
              </div>
              <div class="card-title" style="font-size:14px">{e['name']}</div>
              <div style="font-size:12px;color:var(--muted);margin-bottom:4px">{e['instructor']}</div>
              <div style="font-size:11px;color:var(--muted);margin-bottom:12px">{e['schedule']} &nbsp;·&nbsp; {e['credits']} Credits</div>
              <div style="margin-bottom:10px">
                <div style="display:flex;justify-content:space-between;margin-bottom:4px;font-size:11px">
                  <span style="color:var(--muted)">Progress</span><span style="color:{sc}">{prog}%</span>
                </div>
                <div class="progress-ok"><div class="progress-fill" style="width:{prog}%;background:{sc}"></div></div>
              </div>
              <div style="font-size:11px;color:var(--muted);margin-bottom:12px">Submitted: {sub_count}/{total_assign} assignments</div>
              {next_html}
              <div style="margin-top:14px;display:flex;gap:8px">
                <a href="/moodle/course/{e['id']}" class="btn-ok btn-emerald btn-sm-ok">Open Course</a>
              </div>
            </div>"""
        courses_html += "</div>"

    content = f"""
    <div style="margin-bottom:22px;display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
      <div>
        <div class="section-title">E-Learning Platform</div>
        <div class="section-sub">Your enrolled courses &nbsp;·&nbsp; Authenticated via SAML SSO</div>
      </div>
      <div style="display:flex;gap:8px">
        <a href="/saml/viewer" class="btn-ok btn-muted btn-sm-ok">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" fill="currentColor" viewBox="0 0 16 16" style="margin-right:4px"><path d="M10.5 8a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0z"/><path d="M0 8s3-5.5 8-5.5S16 8 16 8s-3 5.5-8 5.5S0 8 0 8zm8 3.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z"/></svg>
          View SAML Proof
        </a>
      </div>
    </div>
    <div class="card-ok" style="padding:10px 16px;margin-bottom:20px;display:flex;align-items:center;gap:10px;background:rgba(168,85,247,0.06);border-color:rgba(168,85,247,0.2)">
      <span class="badge-ok badge-saml">SAML SSO</span>
      <span style="font-size:12px;color:var(--muted)">Authenticated as <strong style="color:var(--text)">{username}</strong> via OneKey Identity Provider</span>
    </div>
    {courses_html}"""
    return render_dash(content, "elearning", "E-Learning")

@app.route("/moodle/course/<int:cid>")
@login_required
def moodle_course(cid):
    if "moodle_user" not in session:
        return redirect(url_for("moodle"))
    username = session["user"]
    conn = get_db()
    course = conn.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    if not course:
        conn.close(); return redirect(url_for("moodle_home"))
    enroll = conn.execute("SELECT * FROM enrollments WHERE username=? AND course_id=?", (username,cid)).fetchone()
    if not enroll:
        conn.close(); flash("You are not enrolled in this course.", "danger"); return redirect(url_for("moodle_home"))
    assignments = conn.execute("SELECT * FROM assignments WHERE course_id=? ORDER BY due_date", (cid,)).fetchall()
    submissions = {s["assignment_id"]: dict(s) for s in conn.execute("SELECT * FROM submissions WHERE username=? AND assignment_id IN (SELECT id FROM assignments WHERE course_id=?)", (username,cid)).fetchall()}
    announcements = conn.execute("SELECT * FROM announcements WHERE course_id=? ORDER BY posted_at DESC", (cid,)).fetchall()
    grade = conn.execute("SELECT * FROM grades WHERE username=? AND course_id=?", (username,cid)).fetchone()
    materials = conn.execute("SELECT * FROM course_materials WHERE course_id=? ORDER BY week, id", (cid,)).fetchall()
    conn.close()

    # Assignments
    assign_rows = ""
    for a in assignments:
        sub = submissions.get(a["id"])
        due = a["due_date"]
        overdue = due < datetime.utcnow().strftime("%Y-%m-%d")
        if sub:
            ts = sub.get("submitted_at","")[:16].replace("T"," ") if sub.get("submitted_at") else ""
            status_html = f'<span class="badge-ok badge-success">Submitted</span>'
            action_html = f'<div style="font-size:11px;color:var(--muted)">Score: {sub.get("score","Pending")}/{a["max_score"]}<br><span style="font-size:10px">{ts}</span></div>'
        elif overdue:
            status_html = '<span class="badge-ok badge-danger">Overdue</span>'
            action_html = f'<form method="POST" action="/moodle/submit/{a["id"]}"><input name="content" placeholder="Late submission..." style="background:rgba(255,255,255,0.05);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:6px;font-size:11px;width:140px"><button type="submit" class="btn-ok btn-danger btn-sm-ok" style="margin-left:6px">Submit Late</button></form>'
        else:
            status_html = '<span class="badge-ok badge-warn">Pending</span>'
            action_html = f'<form method="POST" action="/moodle/submit/{a["id"]}"><input name="content" placeholder="Your answer..." style="background:rgba(255,255,255,0.05);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:6px;font-size:11px;width:140px"><button type="submit" class="btn-ok btn-emerald btn-sm-ok" style="margin-left:6px">Submit</button></form>'
        assign_rows += f"""<tr>
          <td style="font-weight:600;font-size:12px">{a['title']}</td>
          <td style="color:var(--muted);font-size:12px">{due}</td>
          <td>{status_html}</td>
          <td>{action_html}</td>
        </tr>"""

    # Announcements
    ann_html = ""
    for ann in announcements:
        ts = ann["posted_at"][:10] if ann["posted_at"] else ""
        ann_html += f"""<div style="padding:14px 0;border-bottom:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px">
            <strong style="font-size:13px">{ann['title']}</strong>
            <span style="font-size:11px;color:var(--muted)">{ts}</span>
          </div>
          <p style="font-size:12px;color:var(--muted);margin:0;line-height:1.6">{ann['content']}</p>
        </div>"""
    if not ann_html:
        ann_html = '<div style="text-align:center;padding:24px;color:var(--muted);font-size:13px">No announcements for this course.</div>'

    # Grades
    if grade:
        q,a_,m,f = grade["quiz_score"],grade["assignment_score"],grade["midterm_score"],grade["final_score"]
        total = round(q*0.2 + a_*0.2 + m*0.3 + f*0.3, 1)
        grade_letter = "A" if total>=90 else ("B" if total>=80 else ("C" if total>=70 else ("D" if total>=60 else "F")))
        grade_html = f"""
          <div class="row-ok row-4" style="margin-top:12px">
            <div style="text-align:center;padding:12px;background:rgba(255,255,255,0.03);border-radius:8px">
              <div style="font-size:22px;font-weight:800;color:var(--emerald)">{q}%</div><div style="font-size:11px;color:var(--muted)">Quizzes (20%)</div>
            </div>
            <div style="text-align:center;padding:12px;background:rgba(255,255,255,0.03);border-radius:8px">
              <div style="font-size:22px;font-weight:800;color:var(--cyan)">{a_}%</div><div style="font-size:11px;color:var(--muted)">Assignments (20%)</div>
            </div>
            <div style="text-align:center;padding:12px;background:rgba(255,255,255,0.03);border-radius:8px">
              <div style="font-size:22px;font-weight:800;color:#fbbf24">{m}%</div><div style="font-size:11px;color:var(--muted)">Midterm (30%)</div>
            </div>
            <div style="text-align:center;padding:12px;background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.2);border-radius:8px">
              <div style="font-size:22px;font-weight:800;color:var(--emerald)">{total if total>0 else '—'}%</div>
              <div style="font-size:11px;color:var(--muted)">Total — Grade: <strong>{grade_letter if total>0 else '—'}</strong></div>
            </div>
          </div>
          <div style="margin-top:12px">
            <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px"><span style="color:var(--muted)">Overall progress</span><span style="color:var(--emerald)">{total if total>0 else 0}%</span></div>
            <div class="progress-ok" style="height:6px"><div class="progress-fill" style="width:{total if total>0 else 0}%"></div></div>
          </div>"""
    else:
        grade_html = '<p style="font-size:13px;color:var(--muted)">No grades recorded yet.</p>'

    # Materials
    mat_html = ""
    mat_icon = {"PDF":"<svg xmlns='http://www.w3.org/2000/svg' width='14' height='14' fill='#f87171' viewBox='0 0 16 16'><path d='M14 14V4.5L9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2zM9.5 3A1.5 1.5 0 0 0 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5v2z'/></svg>",
                "Slides":"<svg xmlns='http://www.w3.org/2000/svg' width='14' height='14' fill='#fb923c' viewBox='0 0 16 16'><path d='M0 2a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H4.414a1 1 0 0 0-.707.293L.854 15.146A.5.5 0 0 1 0 14.793V2z'/></svg>",
                "Lab":"<svg xmlns='http://www.w3.org/2000/svg' width='14' height='14' fill='#10b981' viewBox='0 0 16 16'><path d='M14.5 3a.5.5 0 0 1 .5.5v9a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-9a.5.5 0 0 1 .5-.5h13zm-13-1A1.5 1.5 0 0 0 0 3.5v9A1.5 1.5 0 0 0 1.5 14h13a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 14.5 2h-13z'/></svg>"}
    for m in materials:
        icon = mat_icon.get(m["material_type"], mat_icon["PDF"])
        mat_html += f"""<div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border)">
          <div style="flex-shrink:0">{icon}</div>
          <div style="flex:1">
            <div style="font-size:13px;font-weight:600">{m['title']}</div>
            <div style="font-size:11px;color:var(--muted)">Week {m['week']} &nbsp;·&nbsp; {m['material_type']} &nbsp;·&nbsp; {m['description']}</div>
          </div>
          <span class="badge-ok badge-muted" style="font-size:10px">{m['material_type']}</span>
        </div>"""
    if not mat_html:
        mat_html = '<div style="font-size:13px;color:var(--muted)">No materials uploaded yet.</div>'

    content = f"""
    <div style="margin-bottom:20px">
      <a href="/moodle/home" class="btn-ok btn-muted btn-sm-ok" style="margin-bottom:12px">
        <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" fill="currentColor" viewBox="0 0 16 16" style="margin-right:4px"><path fill-rule="evenodd" d="M15 8a.5.5 0 0 0-.5-.5H2.707l3.147-3.146a.5.5 0 1 0-.708-.708l-4 4a.5.5 0 0 0 0 .708l4 4a.5.5 0 0 0 .708-.708L2.707 8.5H14.5A.5.5 0 0 0 15 8z"/></svg>
        Back to Courses
      </a>
      <div class="section-title">{course['name']}</div>
      <div class="section-sub">{course['code']} &nbsp;·&nbsp; {course['instructor']} &nbsp;·&nbsp; {course['credits']} Credits &nbsp;·&nbsp; {course['schedule']}</div>
    </div>
    <div class="row-ok row-3" style="margin-bottom:20px">
      <div style="grid-column:span 2">
        <div class="card-ok card-ok-pad" style="margin-bottom:16px">
          <div class="card-title" style="margin-bottom:4px">Course Overview</div>
          <p style="font-size:13px;color:var(--muted);margin-bottom:0;line-height:1.7">{course['description']}</p>
        </div>
        <div class="card-ok card-ok-pad" style="margin-bottom:16px">
          <div class="card-title" style="margin-bottom:14px">Assignments</div>
          <div class="table-wrap">
            <table class="ok-table">
              <thead><tr><th>Title</th><th>Due Date</th><th>Status</th><th>Action</th></tr></thead>
              <tbody>{assign_rows or '<tr><td colspan="4" style="text-align:center;color:var(--muted)">No assignments for this course.</td></tr>'}</tbody>
            </table>
          </div>
        </div>
        <div class="card-ok card-ok-pad" style="margin-bottom:16px">
          <div class="card-title" style="margin-bottom:4px">Grades</div>
          {grade_html}
        </div>
        <div class="card-ok card-ok-pad">
          <div class="card-title" style="margin-bottom:14px">Course Materials</div>
          {mat_html}
        </div>
      </div>
      <div>
        <div class="card-ok card-ok-pad" style="margin-bottom:16px">
          <div style="margin-bottom:14px">
            <div class="card-title">Course Progress</div>
          </div>
          <div style="font-size:36px;font-weight:800;color:var(--emerald);margin-bottom:6px">{enroll['progress']}%</div>
          <div class="progress-ok" style="height:8px;margin-bottom:8px"><div class="progress-fill" style="width:{enroll['progress']}%"></div></div>
          <div style="font-size:11px;color:var(--muted);margin-top:8px">
            Submitted: {len(submissions)}/{len(assignments)} assignments
          </div>
        </div>
        <div class="card-ok card-ok-pad">
          <div class="card-title" style="margin-bottom:14px">Announcements</div>
          {ann_html}
        </div>
        <div class="card-ok card-ok-pad" style="margin-top:16px;background:rgba(168,85,247,0.05);border-color:rgba(168,85,247,0.2)">
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px">Authentication Proof</div>
          <a href="/saml/viewer" class="btn-ok btn-sm-ok" style="background:rgba(168,85,247,0.15);color:#c084fc;border:1px solid rgba(168,85,247,0.25);width:100%;justify-content:center">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" fill="currentColor" viewBox="0 0 16 16" style="margin-right:4px"><path d="M10.5 8a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0z"/><path d="M0 8s3-5.5 8-5.5S16 8 16 8s-3 5.5-8 5.5S0 8 0 8zm8 3.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z"/></svg>
            View SAML Proof
          </a>
        </div>
      </div>
    </div>"""
    return render_dash(content, "elearning", course["name"])

@app.route("/moodle/submit/<int:aid>", methods=["POST"])
@login_required
def moodle_submit(aid):
    if "moodle_user" not in session:
        return redirect(url_for("moodle"))
    username = session["user"]
    content  = request.form.get("content","").strip()
    conn = get_db()
    assign = conn.execute("SELECT * FROM assignments WHERE id=?", (aid,)).fetchone()
    existing = conn.execute("SELECT id FROM submissions WHERE assignment_id=? AND username=?", (aid,username)).fetchone()
    if existing:
        conn.close(); flash("Assignment already submitted.", "info"); return redirect(request.referrer or url_for("moodle_home"))
    if not content:
        conn.close(); flash("Please provide your submission content.", "danger"); return redirect(request.referrer or url_for("moodle_home"))
    conn.execute("""INSERT INTO submissions (assignment_id,username,content,submitted_at,status)
        VALUES (?,?,?,?,?)""", (aid,username,content,datetime.utcnow().isoformat(),"Submitted"))
    conn.commit()
    conn.close()
    log_event(username,"assignment_submitted","E-Learning","SAML","Success",f"Assignment {aid}: {assign['title'] if assign else ''}")
    flash("Assignment submitted successfully.", "success")
    return redirect(request.referrer or url_for("moodle_home"))

@app.route("/saml/viewer")
@login_required
def saml_viewer():
    conn = get_db()
    packets = conn.execute("SELECT * FROM saml_log ORDER BY id DESC LIMIT 40").fetchall()
    conn.close()
    rows_html = ""
    for p in packets:
        badge_cls = "badge-saml" if "Request" in p["packet_type"] else "badge-success"
        ts = p["captured_at"][:16].replace("T"," ") if p["captured_at"] else ""
        xml_safe = (p["decoded_xml"] or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        rows_html += f"""<div class="card-ok card-ok-pad" style="margin-bottom:14px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px">
            <div style="display:flex;align-items:center;gap:10px">
              <span class="badge-ok {badge_cls}">{p['packet_type']}</span>
              <span style="font-size:13px;font-weight:600">{p['direction']}</span>
            </div>
            <span style="font-size:11px;color:var(--muted)">{ts} &nbsp;·&nbsp; {p['remote_addr']}</span>
          </div>
          <div class="saml-xml">{xml_safe}</div>
        </div>"""

    content = f"""
    <div style="margin-bottom:22px;display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
      <div>
        <div class="section-title">SAML Packet Viewer</div>
        <div class="section-sub">Live capture of AuthnRequest and SAMLResponse packets — educational demonstration</div>
      </div>
      <div style="display:flex;gap:8px">
        <a href="/moodle/login" class="btn-ok btn-emerald btn-sm-ok">Trigger SAML Flow</a>
        <a href="/saml/viewer/clear" class="btn-ok btn-danger btn-sm-ok" onclick="return confirm('Clear all SAML packets?')">Clear Log</a>
      </div>
    </div>
    <div class="card-ok card-ok-pad" style="margin-bottom:20px;background:rgba(168,85,247,0.05);border-color:rgba(168,85,247,0.2)">
      <div style="font-size:12px;font-weight:700;color:var(--muted);margin-bottom:10px">HOW SAML SSO WORKS</div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;font-size:12px">
        <div><strong style="color:#c084fc">1. AuthnRequest</strong><br><span style="color:var(--muted)">SP (E-Learning) creates XML request, base64-encodes it, redirects browser to IdP</span></div>
        <div><strong style="color:#c084fc">2. IdP Authentication</strong><br><span style="color:var(--muted)">OneKey IdP verifies user identity (session/MFA/Google OAuth)</span></div>
        <div><strong style="color:#c084fc">3. SAMLResponse + Assertion</strong><br><span style="color:var(--muted)">IdP builds Response XML with user attributes, auto-POSTs to ACS endpoint</span></div>
      </div>
    </div>
    {rows_html or '<div class="card-ok card-ok-pad" style="text-align:center;color:var(--muted);font-size:13px;padding:40px">No SAML packets captured yet. <a href="/moodle/login" style="color:var(--emerald)">Trigger a SAML flow</a> to see packets here.</div>'}"""
    return render_dash(content, "elearning", "SAML Viewer")

@app.route("/saml/viewer/clear")
@login_required
def saml_viewer_clear():
    conn = get_db()
    conn.execute("DELETE FROM saml_log")
    conn.commit(); conn.close()
    flash("SAML log cleared.", "success")
    return redirect(url_for("saml_viewer"))

# ══════════════════════════════════════════════════════════════════════════════
# LIBRARY (OAuth2)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/library")
@login_required
def library():
    if "library_token" in session:
        return redirect(url_for("library_home"))
    log_event(session["user"],"oauth_flow_start","Digital Library","OAuth2","Success","User initiated OAuth2 authorization flow")
    content = """
    <div style="max-width:560px;margin:60px auto;text-align:center">
      <div class="app-icon-ok icon-cyan" style="width:64px;height:64px;margin:0 auto 20px;display:flex;align-items:center;justify-content:center">
        <svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="none" stroke="#06b6d4" stroke-width="1.6" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M8 14v3m4-3v3m4-3v3M3 21h18M3 10h18M3 7l9-4 9 4M4 10h16v11H4z"/></svg>
      </div>
      <h2 class="section-title" style="margin-bottom:8px">Digital Library</h2>
      <p class="section-sub" style="margin-bottom:28px">Secure access via OAuth 2.0 Authorization Code Flow. The Library app will request permission to access your OneKey identity.</p>
      <div class="card-ok card-ok-pad" style="text-align:left;margin-bottom:20px">
        <div style="font-size:12px;color:var(--muted);margin-bottom:10px;font-weight:700;letter-spacing:0.5px">OAUTH 2.0 FLOW</div>
        <div style="display:flex;flex-direction:column;gap:8px;font-size:12px;color:var(--muted)">
          <div><span class="badge-ok badge-oauth" style="margin-right:8px">1</span> Library redirects you to OneKey Authorization Server</div>
          <div><span class="badge-ok badge-oauth" style="margin-right:8px">2</span> OneKey issues an Authorization Code</div>
          <div><span class="badge-ok badge-oauth" style="margin-right:8px">3</span> Library exchanges code for an Access Token</div>
          <div><span class="badge-ok badge-oauth" style="margin-right:8px">4</span> Library uses token to access your profile</div>
        </div>
      </div>
      <a href="/oauth/authorize?client_id=library-app&redirect_uri=https://localhost:5050/library/callback&response_type=code&state=lib-state-xyz" class="btn-ok btn-cyan" style="font-size:15px;padding:12px 32px">Authorize with OneKey</a>
    </div>"""
    return render_dash(content, "library", "Digital Library")

@app.route("/oauth/authorize")
@login_required
def oauth_authorize():
    client_id    = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    state        = request.args.get("state","")
    response_type= request.args.get("response_type")
    if response_type != "code" or client_id != "library-app" or redirect_uri != "https://localhost:5050/library/callback":
        return "Invalid OAuth2 request", 400
    code       = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
    conn = get_db()
    conn.execute("""INSERT INTO authorization_codes (code,username,client_id,redirect_uri,expires_at)
        VALUES (?,?,?,?,?)""", (code, session["user"], client_id, redirect_uri, expires_at))
    conn.commit(); conn.close()
    log_event(session["user"],"oauth_code_issued","Digital Library","OAuth2","Success",f"Authorization code issued for {client_id}")
    log_oauth_event("authorization_code_issued", client_id, session["user"], "Success", f"code={code[:8]}...")
    return redirect(f"{redirect_uri}?code={code}&state={state}")

@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    code = request.form.get("code")
    if request.form.get("client_id") not in (None, "library-app"):
        return jsonify({"error":"invalid_client"}), 400
    conn = get_db()
    row  = conn.execute("SELECT * FROM authorization_codes WHERE code=?", (code,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error":"invalid_grant","error_description":"Authorization code not found"}), 400
    if row["client_id"] != "library-app" or row["redirect_uri"] != "https://localhost:5050/library/callback":
        conn.close()
        return jsonify({"error":"invalid_grant"}), 400
    if datetime.utcnow() > datetime.fromisoformat(row["expires_at"]):
        conn.execute("DELETE FROM authorization_codes WHERE code=?", (code,))
        conn.commit(); conn.close()
        return jsonify({"error":"invalid_grant","error_description":"Authorization code expired"}), 400
    username = row["username"]
    conn.execute("DELETE FROM authorization_codes WHERE code=?", (code,))
    conn.commit(); conn.close()
    payload = {"sub":username,"iss":"OneKey-University-IdP","aud":"library-app",
               "iat":datetime.utcnow().isoformat(),"exp":(datetime.utcnow()+timedelta(hours=1)).isoformat()}
    token = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    log_event(username,"oauth_token_issued","Digital Library","OAuth2","Success","Access token issued")
    log_oauth_event("access_token_issued","library-app",username,"Success","Bearer token issued")
    return jsonify({"access_token":token,"token_type":"Bearer","expires_in":3600,"scope":"profile email"})

@app.route("/library/callback")
@login_required
def library_callback():
    code = request.args.get("code")
    if not code:
        flash("OAuth2 authorization failed.", "danger")
        return redirect(url_for("library"))
    try:
        with app.test_client() as tc:
            resp = tc.post("/oauth/token", data={"code":code, "client_id":"library-app"})
            if resp.status_code != 200:
                raise Exception("Token exchange failed")
            data = json.loads(resp.data)
        session["library_token"] = data["access_token"]
        log_event(session["user"],"oauth_callback_success","Digital Library","OAuth2","Success","Library authorized via OAuth2")
        return redirect(url_for("library_home"))
    except Exception as e:
        log_event(session.get("user","?"),"oauth_callback_failed","Digital Library","OAuth2","Failed",str(e))
        flash("Library authorization failed. Please try again.", "danger")
        return redirect(url_for("library"))

@app.route("/library/home")
@login_required
def library_home():
    if "library_token" not in session:
        return redirect(url_for("library"))
    username = session["user"]
    search   = request.args.get("q","").strip()
    category = request.args.get("cat","")
    conn = get_db()
    q = "SELECT * FROM library_books WHERE 1=1"
    params = []
    if search:
        q += " AND (title LIKE ? OR author LIKE ?)"
        params += [f"%{search}%", f"%{search}%"]
    if category:
        q += " AND category=?"
        params.append(category)
    q += " ORDER BY title"
    books = conn.execute(q, params).fetchall()
    borrowed_ids = {b["book_id"] for b in conn.execute("SELECT book_id FROM borrowed_books WHERE username=? AND returned_at IS NULL", (username,)).fetchall()}
    categories = [r[0] for r in conn.execute("SELECT DISTINCT category FROM library_books ORDER BY category").fetchall()]
    my_borrowed = conn.execute("""SELECT bb.*, b.title, b.author, b.category FROM borrowed_books bb
        JOIN library_books b ON bb.book_id = b.id
        WHERE bb.username=? AND bb.returned_at IS NULL ORDER BY bb.borrowed_at DESC""", (username,)).fetchall()
    conn.close()
    log_event(username,"library_browsed","Digital Library","OAuth2","Success","Library catalog accessed")

    cat_opts = '<option value="">All Categories</option>' + "".join(f'<option value="{c}" {"selected" if c==category else ""}>{c}</option>' for c in categories)
    books_html = ""
    for b in books:
        avail = b["id"] not in borrowed_ids and b["available"]
        is_mine = b["id"] in borrowed_ids
        if is_mine:
            btn = f'<form method="POST" action="/library/return/{b["id"]}"><button type="submit" class="btn-ok btn-danger btn-sm-ok">Return</button></form>'
            badge = '<span class="badge-ok badge-warn">Borrowed by You</span>'
        elif avail:
            btn = f'<form method="POST" action="/library/borrow/{b["id"]}"><button type="submit" class="btn-ok btn-emerald btn-sm-ok">Borrow</button></form>'
            badge = '<span class="badge-ok badge-success">Available</span>'
        else:
            btn = '<button class="btn-ok btn-muted btn-sm-ok" disabled>Unavailable</button>'
            badge = '<span class="badge-ok badge-danger">Checked Out</span>'
        books_html += f"""<div class="card-ok card-ok-pad">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">
            <span class="badge-ok badge-muted" style="font-size:10px">{b['category']}</span>
            {badge}
          </div>
          <div class="card-title" style="font-size:13px">{b['title']}</div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:6px">{b['author']}</div>
          <div style="font-size:11px;color:#374151;margin-bottom:12px">ISBN: {b['isbn']}</div>
          <p style="font-size:11px;color:var(--muted);margin-bottom:12px;line-height:1.5">{b['description'][:100]}...</p>
          {btn}
        </div>"""

    my_borrow_html = ""
    for mb in my_borrowed:
        due = mb["due_date"][:10] if mb["due_date"] else "—"
        overdue = due < datetime.utcnow().strftime("%Y-%m-%d")
        due_badge = f'<span class="badge-ok badge-danger">Overdue: {due}</span>' if overdue else f'<span class="badge-ok badge-warn">Due: {due}</span>'
        my_borrow_html += f"""<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border)">
          <div><div style="font-size:13px;font-weight:600">{mb['title']}</div><div style="font-size:11px;color:var(--muted)">{mb['author']}</div></div>
          <div style="display:flex;align-items:center;gap:8px">{due_badge}<form method="POST" action="/library/return/{mb['book_id']}"><button type="submit" class="btn-ok btn-danger btn-sm-ok">Return</button></form></div>
        </div>"""

    content = f"""
    <div style="margin-bottom:22px;display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
      <div>
        <div class="section-title">Digital Library</div>
        <div class="section-sub">Academic resources &nbsp;·&nbsp; Authorized via OAuth 2.0</div>
      </div>
      <span class="badge-ok badge-oauth">OAuth 2.0 Access Token</span>
    </div>
    <form method="GET" style="margin-bottom:20px">
      <div class="filter-row">
        <input name="q" value="{search}" placeholder="Search by title or author...">
        <select name="cat">{cat_opts}</select>
        <button type="submit" class="btn-ok btn-cyan btn-sm-ok">Search</button>
        <a href="/library/home" class="btn-ok btn-muted btn-sm-ok">Clear</a>
      </div>
    </form>
    {"<div class='card-ok card-ok-pad' style='margin-bottom:20px'><div class='card-title' style='margin-bottom:12px'>My Borrowed Books</div>" + my_borrow_html + "</div>" if my_borrowed else ""}
    <div class="row-ok row-4">{books_html}</div>"""
    return render_dash(content, "library", "Digital Library")

@app.route("/library/borrow/<int:bid>", methods=["POST"])
@login_required
def library_borrow(bid):
    if "library_token" not in session:
        return redirect(url_for("library"))
    username = session["user"]
    conn = get_db()
    book = conn.execute("SELECT * FROM library_books WHERE id=?", (bid,)).fetchone()
    already = conn.execute("SELECT id FROM borrowed_books WHERE book_id=? AND username=? AND returned_at IS NULL", (bid,username)).fetchone()
    if already:
        conn.close(); flash("You already have this book.", "info"); return redirect(url_for("library_home"))
    if not book or not book["available"]:
        conn.close(); flash("This book is not available.", "danger"); return redirect(url_for("library_home"))
    due = (datetime.utcnow()+timedelta(days=14)).isoformat()
    conn.execute("UPDATE library_books SET available=0 WHERE id=?", (bid,))
    conn.execute("INSERT INTO borrowed_books (book_id,username,borrowed_at,due_date) VALUES (?,?,?,?)",
                 (bid,username,datetime.utcnow().isoformat(),due))
    conn.commit(); conn.close()
    log_event(username,"book_borrowed","Digital Library","OAuth2","Success",f"Borrowed: {book['title']}")
    flash(f"Successfully borrowed '{book['title']}'. Due: {due[:10]}", "success")
    return redirect(url_for("library_home"))

@app.route("/library/return/<int:bid>", methods=["POST"])
@login_required
def library_return(bid):
    if "library_token" not in session:
        return redirect(url_for("library"))
    username = session["user"]
    conn = get_db()
    book = conn.execute("SELECT * FROM library_books WHERE id=?", (bid,)).fetchone()
    conn.execute("UPDATE borrowed_books SET returned_at=? WHERE book_id=? AND username=? AND returned_at IS NULL",
                 (datetime.utcnow().isoformat(),bid,username))
    conn.execute("UPDATE library_books SET available=1 WHERE id=?", (bid,))
    conn.commit(); conn.close()
    log_event(username,"book_returned","Digital Library","OAuth2","Success",f"Returned: {book['title'] if book else bid}")
    flash("Book returned successfully.", "success")
    return redirect(url_for("library_home"))

# ══════════════════════════════════════════════════════════════════════════════
# STUDENT REGISTRATION
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/registration")
@login_required
def registration():
    username = session["user"]
    conn = get_db()
    my_regs = conn.execute("""SELECT rc.*, sr.id as reg_id, sr.registered_at
        FROM registration_courses rc
        JOIN student_registrations sr ON rc.id=sr.course_id
        WHERE sr.username=? ORDER BY rc.code""", (username,)).fetchall()
    my_ids  = {r["id"] for r in my_regs}
    total_credits = sum(r["credits"] for r in my_regs)
    available = conn.execute("SELECT * FROM registration_courses ORDER BY code").fetchall()
    conn.close()
    log_event(username,"registration_viewed","Registration","App","Success","Student registration page accessed")

    # Credit progress bar color
    credits_color = "#ef4444" if total_credits >= 18 else ("#fbbf24" if total_credits >= 15 else "#10b981")
    credits_pct = min(int(total_credits / 18 * 100), 100)

    my_rows = ""
    for r in my_regs:
        my_rows += f"""<tr>
          <td><span class="badge-ok badge-muted" style="font-size:10px">{r['code']}</span></td>
          <td style="font-weight:600;font-size:13px">{r['name']}</td>
          <td style="color:var(--muted)">{r['credits']}</td>
          <td style="color:var(--muted);font-size:12px">{r['instructor']}</td>
          <td style="color:var(--muted);font-size:12px">{r['schedule']} {('· Room ' + r['room']) if ('room' in r.keys() and r['room']) else ''}</td>
          <td>
            <form method="POST" action="/registration/drop/{r['id']}" style="display:inline">
              <button type="submit" class="btn-ok btn-danger btn-sm-ok" onclick="return confirm('Drop {r['name']}?')">Drop</button>
            </form>
          </td>
        </tr>"""

    avail_rows = ""
    for r in available:
        if r["id"] in my_ids:
            action = '<span class="badge-ok badge-success" style="font-size:11px">Registered</span>'
            seats_badge = f'<span class="badge-ok {"badge-success" if r["seats_available"]>5 else "badge-warn"}">{r["seats_available"]}/{r["seats_total"]}</span>'
        elif r["seats_available"] <= 0:
            action = '<button class="btn-ok btn-muted btn-sm-ok" disabled>Full</button>'
            seats_badge = '<span class="badge-ok badge-danger">Full</span>'
        elif total_credits + r["credits"] > 18:
            action = '<span class="badge-ok badge-warn" style="font-size:11px">Credit limit</span>'
            seats_badge = f'<span class="badge-ok {"badge-success" if r["seats_available"]>5 else "badge-warn"}">{r["seats_available"]}/{r["seats_total"]}</span>'
        else:
            action = f'<form method="POST" action="/registration/register/{r["id"]}"><button type="submit" class="btn-ok btn-emerald btn-sm-ok">Register</button></form>'
            seats_badge = f'<span class="badge-ok {"badge-success" if r["seats_available"]>5 else ("badge-warn" if r["seats_available"]>0 else "badge-danger")}">{r["seats_available"]}/{r["seats_total"]}</span>'
        avail_rows += f"""<tr>
          <td><span class="badge-ok badge-muted" style="font-size:10px">{r['code']}</span></td>
          <td style="font-weight:600;font-size:13px">{r['name']}</td>
          <td style="color:var(--muted)">{r['credits']}</td>
          <td style="color:var(--muted);font-size:12px">{r['instructor']}</td>
          <td style="color:var(--muted);font-size:12px">{r['schedule']}</td>
          <td>{seats_badge}</td>
          <td>{action}</td>
        </tr>"""

    # Weekly schedule grid
    days_order = ["Sun","Mon","Tue","Wed","Thu"]
    day_labels = {"Sun":"Sunday","Mon":"Monday","Tue":"Tuesday","Wed":"Wednesday","Thu":"Thursday"}
    sched_cells = {d: [] for d in days_order}
    colors = ["rgba(16,185,129,0.15)","rgba(6,182,212,0.15)","rgba(168,85,247,0.15)","rgba(251,146,60,0.15)","rgba(239,68,68,0.15)"]
    border_colors = ["rgba(16,185,129,0.4)","rgba(6,182,212,0.4)","rgba(168,85,247,0.4)","rgba(251,146,60,0.4)","rgba(239,68,68,0.4)"]
    for idx, r in enumerate(my_regs):
        days_str = r["days"] if ("days" in r.keys() and r["days"]) else ""
        for day in days_order:
            if day in days_str:
                sched_cells[day].append((r["code"], r["name"], r["start_time"] or "", r["end_time"] or "", colors[idx % len(colors)], border_colors[idx % len(border_colors)]))

    week_grid = ""
    for day in days_order:
        courses_in_day = sched_cells[day]
        if courses_in_day:
            blocks = "".join(f"""<div style="background:{bg};border:1px solid {brd};border-radius:6px;padding:8px 10px;margin-bottom:6px">
              <div style="font-size:11px;font-weight:700;color:var(--text)">{code}</div>
              <div style="font-size:10px;color:var(--muted)">{name[:28]}{'...' if len(name)>28 else ''}</div>
              <div style="font-size:10px;color:var(--muted)">{st}–{et}</div>
            </div>""" for code,name,st,et,bg,brd in courses_in_day)
        else:
            blocks = '<div style="font-size:11px;color:rgba(148,163,184,0.3);text-align:center;padding:16px 0">—</div>'
        week_grid += f"""<div>
          <div style="font-size:11px;font-weight:700;color:var(--muted);margin-bottom:8px;text-align:center;padding-bottom:6px;border-bottom:1px solid var(--border)">{day_labels[day]}</div>
          {blocks}
        </div>"""

    # Summary cards
    earliest = min((r["start_time"] for r in my_regs if ("start_time" in r.keys() and r["start_time"])), default="—")
    low_seat_courses = [
        r for r in available
        if ("seats_available" in r.keys() and r["seats_available"] <= 3)
        and r["id"] not in my_ids
    ]
    seat_warning = f'<span class="badge-ok badge-warn">{len(low_seat_courses)} course(s) have 3 or fewer seats remaining</span>' if low_seat_courses else '<span class="badge-ok badge-success">Seat availability is normal</span>'

    content = f"""
    <div style="margin-bottom:22px">
      <div class="section-title">Student Registration</div>
      <div class="section-sub">Semester course registration &nbsp;·&nbsp; Maximum 18 credits per semester</div>
    </div>

    <div class="row-ok row-4" style="margin-bottom:20px">
      <div class="stat-card">
        <div style="display:flex;justify-content:space-between">
          <div><div class="stat-value" style="color:#c084fc">{len(my_regs)}</div><div class="stat-label">Courses Registered</div></div>
          <div class="stat-icon"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="rgba(168,85,247,0.4)" viewBox="0 0 16 16"><path d="M3 2h10a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1zm9 1H4v10h8V3z"/><path d="M5 5.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5zm0 2a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5zm0 2a.5.5 0 0 1 .5-.5h2a.5.5 0 0 1 0 1h-2a.5.5 0 0 1-.5-.5z"/></svg></div>
        </div>
      </div>
      <div class="stat-card">
        <div style="display:flex;justify-content:space-between">
          <div><div class="stat-value" style="color:{credits_color}">{total_credits}</div><div class="stat-label">Credits / 18</div></div>
          <div class="stat-icon" style="color:{credits_color}"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="currentColor" viewBox="0 0 16 16"><path d="M10.854 7.146a.5.5 0 0 1 0 .708l-3 3a.5.5 0 0 1-.708 0l-1.5-1.5a.5.5 0 1 1 .708-.708L7.5 9.793l2.646-2.647a.5.5 0 0 1 .708 0z"/><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1v-1z"/></svg></div>
        </div>
        <div class="progress-ok" style="margin-top:10px;height:4px"><div class="progress-fill" style="width:{credits_pct}%;background:{credits_color}"></div></div>
      </div>
      <div class="stat-card">
        <div style="display:flex;justify-content:space-between">
          <div><div class="stat-value text-em">{18-total_credits}</div><div class="stat-label">Credits Remaining</div></div>
          <div class="stat-icon"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="rgba(16,185,129,0.4)" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8 4a.905.905 0 0 0-.9.995l.35 3.507a.552.552 0 0 0 1.1 0l.35-3.507A.905.905 0 0 0 8 4zm.002 6a1 1 0 1 0 0 2 1 1 0 0 0 0-2z"/></svg></div>
        </div>
      </div>
      <div class="stat-card">
        <div><div class="stat-value text-cy">{earliest}</div><div class="stat-label">Earliest Class</div></div>
        <div style="margin-top:10px">{seat_warning}</div>
      </div>
    </div>

    {"<div class='card-ok card-ok-pad' style='margin-bottom:20px'><div class='card-title' style='margin-bottom:14px'>My Registered Courses</div><div class='table-wrap'><table class='ok-table'><thead><tr><th>Code</th><th>Course</th><th>Credits</th><th>Instructor</th><th>Schedule</th><th>Action</th></tr></thead><tbody>" + my_rows + "</tbody></table></div></div>" if my_regs else ""}

    {"<div class='card-ok card-ok-pad' style='margin-bottom:20px'><div class='card-title' style='margin-bottom:12px'>Weekly Schedule</div><div style='display:grid;grid-template-columns:repeat(5,1fr);gap:10px'>" + week_grid + "</div></div>" if my_regs else ""}

    <div class="card-ok card-ok-pad">
      <div class="card-title" style="margin-bottom:14px">Available Courses</div>
      <div class="table-wrap">
        <table class="ok-table">
          <thead><tr><th>Code</th><th>Course</th><th>Credits</th><th>Instructor</th><th>Schedule</th><th>Seats</th><th>Action</th></tr></thead>
          <tbody>{avail_rows}</tbody>
        </table>
      </div>
    </div>"""
    return render_dash(content, "registration", "Student Registration")

@app.route("/registration/register/<int:cid>", methods=["POST"])
@login_required
def reg_register(cid):
    username = session["user"]
    conn = get_db()
    course = conn.execute("SELECT * FROM registration_courses WHERE id=?", (cid,)).fetchone()
    if not course:
        conn.close(); flash("Course not found.", "danger"); return redirect(url_for("registration"))
    # Duplicate check
    already = conn.execute("SELECT id FROM student_registrations WHERE username=? AND course_id=?", (username, cid)).fetchone()
    if already:
        conn.close(); flash("You are already registered for this course.", "info"); return redirect(url_for("registration"))
    if course["seats_available"] <= 0:
        conn.close(); flash("No seats available in this course.", "danger"); return redirect(url_for("registration"))
    # Credit check
    total = conn.execute("""SELECT COALESCE(SUM(rc.credits),0) FROM registration_courses rc
        JOIN student_registrations sr ON rc.id=sr.course_id WHERE sr.username=?""", (username,)).fetchone()[0]
    if total + course["credits"] > 18:
        conn.close(); flash("Registration would exceed the 18-credit limit.", "danger"); return redirect(url_for("registration"))

    # Schedule conflict detection
    new_days = set((course["days"] or "").split(","))
    new_start = course["start_time"] or ""
    new_end   = course["end_time"] or ""
    if new_days and new_start and new_end:
        my_regs = conn.execute("""SELECT rc.* FROM registration_courses rc
            JOIN student_registrations sr ON rc.id=sr.course_id WHERE sr.username=?""", (username,)).fetchall()
        for r in my_regs:
            r_days = set((r["days"] or "").split(","))
            r_start = r["start_time"] or ""
            r_end   = r["end_time"] or ""
            if not r_days or not r_start: continue
            # Check day overlap
            if new_days & r_days:
                # Check time overlap (simple string compare for HH:MM format)
                if new_start < r_end and new_end > r_start:
                    conn.close()
                    log_event(username,"schedule_conflict_detected","Registration","App","Failed",f"Conflict: {course['code']} vs {r['code']}")
                    flash(f"Schedule conflict with {r['code']} {r['name']}.", "danger")
                    return redirect(url_for("registration"))

    try:
        conn.execute("INSERT INTO student_registrations (username,course_id,registered_at) VALUES (?,?,?)",
                     (username,cid,datetime.utcnow().isoformat()))
        conn.execute("UPDATE registration_courses SET seats_available=seats_available-1 WHERE id=?", (cid,))
        conn.commit()
        log_event(username,"course_registered","Registration","App","Success",f"Registered: {course['name']}")
        flash(f"Successfully registered for {course['name']}.", "success")
    except Exception:
        conn.rollback()
        flash("You are already registered for this course.", "info")
    conn.close()
    return redirect(url_for("registration"))

@app.route("/registration/drop/<int:cid>", methods=["POST"])
@login_required
def reg_drop(cid):
    username = session["user"]
    conn = get_db()
    course = conn.execute("SELECT * FROM registration_courses WHERE id=?", (cid,)).fetchone()
    conn.execute("DELETE FROM student_registrations WHERE username=? AND course_id=?", (username,cid))
    conn.execute("UPDATE registration_courses SET seats_available=seats_available+1 WHERE id=?", (cid,))
    conn.commit(); conn.close()
    log_event(username,"course_dropped","Registration","App","Success",f"Dropped: {course['name'] if course else cid}")
    flash("Course dropped successfully.", "success")
    return redirect(url_for("registration"))

# ══════════════════════════════════════════════════════════════════════════════
# FACULTY PORTAL + SMS OTP
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/faculty")
@login_required
def faculty():
    user = get_current_user()
    username = session["user"]
    role = user.get("role","student")

    if role not in ("faculty","admin"):
        log_event(username,"faculty_access_denied","Faculty Portal","Authorization","Failed",f"Role {role} denied access")
        auth_method = "Google OAuth" if user.get("auth_provider") == "google" else "Local + MFA"
        content = f"""
        <div style="max-width:560px;margin:60px auto">
          <div style="text-align:center;margin-bottom:28px">
            <div style="width:80px;height:80px;border-radius:20px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);display:flex;align-items:center;justify-content:center;margin:0 auto 20px">
              <svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" fill="#f87171" viewBox="0 0 16 16"><path d="M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2z"/></svg>
            </div>
            <h2 class="section-title" style="margin-bottom:8px">Access Restricted</h2>
            <p style="color:var(--muted);font-size:14px;line-height:1.7">
              You are authenticated through OneKey, but your current role does not authorize access to the Faculty Portal.
            </p>
          </div>
          <div class="card-ok card-ok-pad" style="margin-bottom:16px">
            <div class="card-title" style="margin-bottom:14px">Current Session</div>
            <div class="security-item" style="padding:8px 0"><span class="security-label">Authenticated User</span><span class="security-value">{username}</span></div>
            <div class="security-item" style="padding:8px 0"><span class="security-label">Current Role</span><span class="security-value">{role.title()}</span></div>
            <div class="security-item" style="padding:8px 0"><span class="security-label">Authentication Method</span><span class="security-value">{auth_method}</span></div>
            <div class="security-item" style="padding:8px 0;border-bottom:none"><span class="security-label">Access Decision</span><span class="badge-ok badge-danger">Denied</span></div>
          </div>
          <div class="card-ok card-ok-pad" style="margin-bottom:20px;background:rgba(6,182,212,0.05);border-color:rgba(6,182,212,0.2)">
            <div class="card-title" style="margin-bottom:10px;color:var(--cyan)">Authentication vs Authorization</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;font-size:12px">
              <div>
                <div style="font-weight:700;color:var(--emerald);margin-bottom:4px">Authentication</div>
                <div style="color:var(--muted);line-height:1.6">Verifies who you are using OneKey SSO. You have been successfully authenticated.</div>
              </div>
              <div>
                <div style="font-weight:700;color:#f87171;margin-bottom:4px">Authorization</div>
                <div style="color:var(--muted);line-height:1.6">Decides what you can access based on your role. Faculty Portal requires the faculty or admin role.</div>
              </div>
            </div>
          </div>
          <div style="text-align:center">
            <a href="/dashboard" class="btn-ok btn-muted">Return to Dashboard</a>
          </div>
        </div>"""
        return render_dash(content, "faculty", "Faculty Portal")

    # Faculty/Admin: require SMS OTP step-up
    if not session.get("faculty_sms_verified"):
        return redirect(url_for("faculty_sms"))

    log_event(username,"faculty_portal_accessed","Faculty Portal","Authorization","Success",f"Role: {role}")
    conn = get_db()
    courses = conn.execute("SELECT * FROM courses ORDER BY code").fetchall()
    students = conn.execute("""SELECT u.username, u.email, u.role, u.created_at,
        COUNT(DISTINCT sr.course_id) as reg_courses,
        COUNT(DISTINCT e.course_id) as enrolled_courses
        FROM users u
        LEFT JOIN student_registrations sr ON u.username=sr.username
        LEFT JOIN enrollments e ON u.username=e.username
        WHERE u.role='student' GROUP BY u.username ORDER BY u.username""").fetchall()
    notes = conn.execute("SELECT * FROM advising_notes ORDER BY created_at DESC LIMIT 10").fetchall()
    conn.close()

    course_rows = "".join(f"""<tr>
      <td><span class="badge-ok badge-muted" style="font-size:10px">{c['code']}</span></td>
      <td style="font-weight:600">{c['name']}</td>
      <td style="color:var(--muted)">{c['credits']}</td>
      <td style="color:var(--muted)">{c['instructor']}</td>
      <td style="color:var(--muted)">{c['schedule']}</td>
    </tr>""" for c in courses)

    student_rows = "".join(f"""<tr>
      <td style="font-weight:600">{s['username']}</td>
      <td style="color:var(--muted)">{s['email']}</td>
      <td style="color:var(--muted)">{s['reg_courses']}</td>
      <td style="color:var(--muted)">{s['enrolled_courses']}</td>
      <td><span class="badge-ok badge-success">Active</span></td>
    </tr>""" for s in students)

    notes_html = "".join(f"""<div style="padding:12px 0;border-bottom:1px solid var(--border)">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px">
        <strong style="font-size:13px">Re: {n['student_username']}</strong>
        <span style="font-size:11px;color:var(--muted)">{n['created_at'][:10]}</span>
      </div>
      <p style="font-size:12px;color:var(--muted);margin:0">{n['note']}</p>
    </div>""" for n in notes)

    grade_form = """
    <div class="form-ok" style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
      <div><label>Student Username</label><input placeholder="e.g. student1"></div>
      <div><label>Course</label><select><option>Authentication &amp; Security Models</option><option>Network Security</option><option>Database Systems</option></select></div>
      <div><label>Quiz Score (%)</label><input type="number" min="0" max="100" placeholder="85"></div>
      <div><label>Assignment Score (%)</label><input type="number" min="0" max="100" placeholder="90"></div>
      <div><label>Midterm Score (%)</label><input type="number" min="0" max="100" placeholder="78"></div>
      <div style="display:flex;align-items:flex-end"><button type="button" onclick="alert('Grade saved (demo mode)')" class="btn-ok btn-emerald-solid" style="width:100%">Save Grade</button></div>
    </div>"""

    content = f"""
    <div style="margin-bottom:22px">
      <div class="section-title">Faculty Portal</div>
      <div class="section-sub">Academic management &nbsp;·&nbsp; Role: <span class="text-em">{role.title()}</span> &nbsp;·&nbsp; Step-up SMS OTP verified</div>
    </div>
    <div class="card-ok card-ok-pad" style="margin-bottom:20px;background:rgba(6,182,212,0.05);border-color:rgba(6,182,212,0.2)">
      <div style="display:flex;align-items:center;gap:12px">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="var(--cyan)" viewBox="0 0 16 16"><path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.725 10.725 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.615.615 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.775 11.775 0 0 1-2.517 2.453 7.159 7.159 0 0 1-1.048.625c-.28.132-.581.24-.883.24s-.604-.108-.883-.24a7.158 7.158 0 0 1-1.048-.625 11.777 11.777 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 62.456 62.456 0 0 1 5.072.56z"/></svg>
        <div>
          <div style="font-size:13px;font-weight:600;color:var(--cyan)">Step-Up Authentication Verified</div>
          <div style="font-size:11px;color:var(--muted)">SMS OTP confirmed for Faculty Portal access. OneKey authentication + SMS OTP step-up.</div>
        </div>
      </div>
    </div>
    <div class="row-ok row-2" style="margin-bottom:20px">
      <div class="card-ok card-ok-pad">
        <div class="card-title" style="margin-bottom:14px">Course Catalog</div>
        <div class="table-wrap">
          <table class="ok-table">
            <thead><tr><th>Code</th><th>Course Name</th><th>Credits</th><th>Instructor</th><th>Schedule</th></tr></thead>
            <tbody>{course_rows}</tbody>
          </table>
        </div>
      </div>
      <div>
        <div class="card-ok card-ok-pad" style="margin-bottom:16px">
          <div class="card-title" style="margin-bottom:14px">Grade Entry</div>
          {grade_form}
        </div>
        <div class="card-ok card-ok-pad">
          <div class="card-title" style="margin-bottom:14px">Advising Notes</div>
          {notes_html or '<p style="font-size:12px;color:var(--muted)">No advising notes.</p>'}
        </div>
      </div>
    </div>
    <div class="card-ok card-ok-pad">
      <div class="card-title" style="margin-bottom:14px">Student Directory</div>
      <div class="table-wrap">
        <table class="ok-table">
          <thead><tr><th>Username</th><th>Email</th><th>Registered Courses</th><th>Enrolled Courses</th><th>Status</th></tr></thead>
          <tbody>{student_rows}</tbody>
        </table>
      </div>
    </div>"""
    return render_dash(content, "faculty", "Faculty Portal")

@app.route("/faculty/sms")
@login_required
def faculty_sms():
    user = get_current_user()
    role = user.get("role","student")
    if role not in ("faculty","admin"):
        return redirect(url_for("faculty"))
    username = session["user"]
    code = generate_sms_otp()
    log_event(username,"sms_otp_sent","Faculty Portal","SMS OTP","Success","SMS OTP generated for Faculty Portal step-up")

    content = f"""
    <div style="max-width:480px;margin:60px auto">
      <div style="text-align:center;margin-bottom:28px">
        <div style="width:72px;height:72px;border-radius:18px;background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.25);display:flex;align-items:center;justify-content:center;margin:0 auto 20px">
          <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="var(--cyan)" viewBox="0 0 16 16"><path d="M11 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h6zM5 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2H5z"/><path d="M8 14a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"/></svg>
        </div>
        <div class="section-title" style="margin-bottom:8px">SMS Verification Required</div>
        <p style="font-size:13px;color:var(--muted);line-height:1.7">Faculty Portal requires an additional verification step. A one-time code has been sent to your registered phone.</p>
      </div>
      <div class="card-ok card-ok-pad" style="margin-bottom:16px;background:rgba(6,182,212,0.05);border-color:rgba(6,182,212,0.2)">
        <div style="font-size:12px;color:var(--muted);margin-bottom:4px">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" fill="var(--cyan)" viewBox="0 0 16 16" style="margin-right:4px"><path d="M16 8c0 3.866-3.582 7-8 7a9.06 9.06 0 0 1-2.347-.306c-.584.296-1.925.864-4.181 1.234-.2.032-.352-.176-.273-.362.354-.836.674-1.95.77-2.966C.744 11.37 0 9.76 0 8c0-3.866 3.582-7 8-7s8 3.134 8 7z"/></svg>
          Demo SMS sent to registered phone ending in 1234
        </div>
      </div>
      <form method="POST" action="/faculty/sms/verify" class="card-ok card-ok-pad" style="display:block">
        <div style="margin-bottom:16px">
          <label style="font-size:12px;font-weight:600;color:var(--muted);display:block;margin-bottom:6px">Enter 6-Digit OTP Code</label>
          <input name="otp" maxlength="6" placeholder="000000" autocomplete="off" autofocus
            style="width:100%;padding:14px;text-align:center;font-size:28px;letter-spacing:12px;font-family:monospace;background:rgba(255,255,255,0.05);border:1px solid var(--border);border-radius:10px;color:var(--text);outline:none">
        </div>
        <button type="submit" class="btn-ok btn-cyan" style="width:100%;justify-content:center;padding:11px;font-size:14px">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" style="margin-right:6px"><path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.725 10.725 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.615.615 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524z"/></svg>
          Verify OTP
        </button>
      </form>
      <div class="card-ok card-ok-pad" style="margin-top:14px;background:rgba(251,191,36,0.05);border-color:rgba(251,191,36,0.2)">
        <div style="font-size:11px;font-weight:700;color:#fbbf24;margin-bottom:6px">Demo Mode — Educational Simulation</div>
        <div style="font-size:12px;color:var(--muted)">In a real system, the OTP would be delivered via SMS. For this educational demo, your code is:</div>
        <div style="font-size:28px;font-weight:900;font-family:monospace;color:#fbbf24;text-align:center;letter-spacing:8px;padding:10px 0">{code}</div>
        <div style="font-size:11px;color:var(--muted)">This code expires in 5 minutes.</div>
      </div>
      <div style="text-align:center;margin-top:16px">
        <a href="/dashboard" class="btn-ok btn-muted btn-sm-ok">Cancel</a>
      </div>
    </div>"""
    return render_dash(content, "faculty", "Faculty Portal — SMS Verification")

@app.route("/faculty/sms/verify", methods=["POST"])
@login_required
def faculty_sms_verify():
    username = session["user"]
    entered = request.form.get("otp","").strip()
    stored_code    = session.get("faculty_sms_code")
    stored_expires = session.get("faculty_sms_expires")

    if not stored_code:
        flash("No OTP session found. Please try again.", "danger")
        return redirect(url_for("faculty_sms"))

    # Check expiry
    try:
        if datetime.utcnow() > datetime.fromisoformat(stored_expires):
            session.pop("faculty_sms_code", None)
            session.pop("faculty_sms_expires", None)
            log_event(username,"sms_otp_expired","Faculty Portal","SMS OTP","Failed","OTP expired")
            flash("OTP has expired. A new code has been sent.", "danger")
            return redirect(url_for("faculty_sms"))
    except Exception:
        pass

    if entered == stored_code:
        session["faculty_sms_verified"] = True
        session.pop("faculty_sms_code", None)
        session.pop("faculty_sms_expires", None)
        log_event(username,"sms_otp_success","Faculty Portal","SMS OTP","Success","SMS OTP verified — Faculty Portal access granted")
        flash("SMS OTP verified. Welcome to the Faculty Portal.", "success")
        return redirect(url_for("faculty"))
    else:
        log_event(username,"sms_otp_failed","Faculty Portal","SMS OTP","Failed","Wrong OTP entered")
        flash("Invalid OTP code. Please try again.", "danger")
        return redirect(url_for("faculty_sms"))

# ══════════════════════════════════════════════════════════════════════════════
# ACCOUNT SECURITY
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/security")
@login_required
def security():
    user = get_current_user()
    username = session["user"]
    conn = get_db()
    recent_logs = conn.execute("SELECT * FROM audit_logs WHERE username=? ORDER BY id DESC LIMIT 10", (username,)).fetchall()
    attempts = conn.execute("SELECT * FROM login_attempts WHERE identifier=?", (username,)).fetchone()
    conn.close()
    log_event(username,"security_page_viewed","OneKey","App","Success","Account security page accessed")

    provider = user.get("auth_provider","local")
    mfa_status = "Enabled" if (provider == "local" and user.get("mfa_secret")) else ("N/A (Google OAuth)" if provider == "google" else "Not Configured")
    login_at = session.get("login_at","")
    if login_at:
        try: login_at = datetime.fromisoformat(login_at).strftime("%b %d, %Y at %H:%M UTC")
        except: pass
    last_login = user.get("last_login","")
    if last_login:
        try: last_login = datetime.fromisoformat(last_login).strftime("%b %d, %Y at %H:%M UTC")
        except: pass

    logs_html = ""
    proto_map_sec = {
        "SAML":"badge-saml","OAuth2":"badge-oauth","MFA":"badge-info",
        "Google OAuth":"badge-cyan","CAPTCHA":"badge-warn","SMS OTP":"badge-info",
        "Authorization":"badge-danger",
    }
    for lg in recent_logs:
        ts = lg["timestamp"][:16].replace("T"," ") if lg["timestamp"] else ""
        status_c = "badge-success" if lg["status"]=="Success" else "badge-danger"
        proto_c = proto_map_sec.get(lg["protocol"],"badge-muted")
        logs_html += f"""<tr>
          <td style="color:var(--muted);font-size:11px">{ts}</td>
          <td style="font-size:12px">{lg['event_type']}</td>
          <td><span class="badge-ok {proto_c}" style="font-size:10px">{lg['protocol']}</span></td>
          <td><span class="badge-ok {status_c}" style="font-size:10px">{lg['status']}</span></td>
          <td style="font-size:11px;color:var(--muted)">{lg['details'][:60]}</td>
        </tr>"""

    # Security layers config
    layers = [
        ("1", "HTTPS Encrypted Connection",
         "All traffic between your browser and the server is encrypted using TLS. No data is transmitted in plaintext.",
         "badge-success", "Active"),
        ("2", "Password Verification",
         "Local accounts require a username and password. Passwords are hashed using bcrypt before storage.",
         "badge-success" if provider=="local" else "badge-muted",
         "Active" if provider=="local" else "N/A (Google OAuth)"),
        ("3", "Math CAPTCHA",
         "A simple arithmetic CAPTCHA is required on every local login attempt to block automated bots.",
         "badge-success" if provider=="local" else "badge-muted",
         "Active" if provider=="local" else "N/A (Google OAuth)"),
        ("4", "Google Authenticator MFA",
         "Local users must enter a 6-digit TOTP code from Google Authenticator after each password login.",
         "badge-success" if (provider=="local" and user.get("mfa_secret")) else "badge-muted",
         "Enabled" if (provider=="local" and user.get("mfa_secret")) else "N/A"),
        ("5", "Google OAuth",
         "Google users authenticate directly through Google's identity platform without a local password.",
         "badge-success" if provider=="google" else "badge-muted",
         "Active" if provider=="google" else "N/A (Local Account)"),
        ("6", "Role-Based Authorization",
         "Access to sensitive portals is controlled by the user's assigned role (student, faculty, admin).",
         "badge-success", f"Role: {user.get('role','student').title()}"),
        ("7", "SMS OTP Step-Up",
         "Faculty Portal requires an additional 6-digit SMS OTP after login as a step-up authentication layer.",
         "badge-success" if user.get("role") in ("faculty","admin") else "badge-muted",
         "Required for Faculty Portal" if user.get("role") in ("faculty","admin") else "Not applicable for this role"),
        ("8", "Audit Logging",
         "Every authentication event, access attempt, and protocol exchange is logged with timestamp and status.",
         "badge-success", "Active — all events logged"),
    ]

    layer_cards = ""
    for num, title, desc, badge_cls, status in layers:
        layer_cards += f"""<div class="card-ok card-ok-pad" style="display:flex;gap:16px;align-items:flex-start">
          <div style="width:32px;height:32px;border-radius:8px;background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.2);
               display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:800;color:var(--emerald);flex-shrink:0">{num}</div>
          <div style="flex:1">
            <div style="font-size:13px;font-weight:700;color:var(--text);margin-bottom:4px">{title}</div>
            <div style="font-size:11px;color:var(--muted);line-height:1.6;margin-bottom:6px">{desc}</div>
            <span class="badge-ok {badge_cls}" style="font-size:10px">{status}</span>
          </div>
        </div>"""

    content = f"""
    <div style="margin-bottom:22px">
      <div class="section-title">Account Security</div>
      <div class="section-sub">Security configuration, active layers, and recent activity</div>
    </div>
    <div class="row-ok row-2" style="margin-bottom:20px">
      <div class="card-ok card-ok-pad">
        <div class="card-title" style="margin-bottom:16px">Identity &amp; Authentication</div>
        <div class="security-item"><span class="security-label">Username</span><span class="security-value">{user['username']}</span></div>
        <div class="security-item"><span class="security-label">Email</span><span class="security-value">{user.get('email','—')}</span></div>
        <div class="security-item"><span class="security-label">Role</span><span class="security-value">{user.get('role','student').title()}</span></div>
        <div class="security-item"><span class="security-label">Auth Provider</span><span class="security-value">{"Google OAuth" if provider=="google" else "Local Account"}</span></div>
        <div class="security-item"><span class="security-label">MFA Status</span><span class="badge-ok {'badge-success' if 'Enabled' in mfa_status else 'badge-muted'}">{mfa_status}</span></div>
        <div class="security-item"><span class="security-label">Account Created</span><span class="security-value" style="font-size:12px">{user.get('created_at','—')[:10]}</span></div>
      </div>
      <div class="card-ok card-ok-pad">
        <div class="card-title" style="margin-bottom:16px">Session &amp; Connection</div>
        <div class="security-item"><span class="security-label">Session Status</span><span class="badge-ok badge-success">Active</span></div>
        <div class="security-item"><span class="security-label">Session Started</span><span class="security-value" style="font-size:12px">{login_at or '—'}</span></div>
        <div class="security-item"><span class="security-label">Last Login</span><span class="security-value" style="font-size:12px">{last_login or '—'}</span></div>
        <div class="security-item"><span class="security-label">Connection</span><span class="badge-ok badge-success">HTTPS / TLS Encrypted</span></div>
        <div class="security-item"><span class="security-label">Failed Attempts</span><span class="security-value">{attempts['failed_count'] if attempts else 0}</span></div>
        <div class="security-item" style="border-bottom:none">
          <span class="security-label">Lock Status</span>
          {'<span class="badge-ok badge-danger">Temporarily Locked</span>' if (attempts and attempts['locked_until'] and datetime.utcnow() < datetime.fromisoformat(attempts['locked_until'])) else '<span class="badge-ok badge-success">Unlocked</span>'}
        </div>
        <div style="margin-top:16px">
          <button onclick="alert('All other sessions terminated (demo mode)')" class="btn-ok btn-danger btn-sm-ok">Logout All Sessions</button>
        </div>
      </div>
    </div>
    <div style="margin-bottom:20px">
      <div class="section-title" style="font-size:15px;margin-bottom:14px">Security Layers</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">{layer_cards}</div>
    </div>
    <div class="card-ok card-ok-pad">
      <div class="card-title" style="margin-bottom:14px">Recent Security Events</div>
      <div class="table-wrap">
        <table class="ok-table">
          <thead><tr><th>Timestamp</th><th>Event</th><th>Protocol</th><th>Status</th><th>Details</th></tr></thead>
          <tbody>{logs_html or '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:20px">No events recorded yet.</td></tr>'}</tbody>
        </table>
      </div>
    </div>"""
    return render_dash(content, "security", "Account Security")

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT CENTER
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/audit")
@login_required
def audit():
    username = session["user"]
    proto_f  = request.args.get("protocol","")
    status_f = request.args.get("status","")
    app_f    = request.args.get("app","")
    search_f = request.args.get("q","").strip()
    q = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    if proto_f:  q += " AND protocol=?";  params.append(proto_f)
    if status_f: q += " AND status=?";    params.append(status_f)
    if app_f:    q += " AND app_name=?";  params.append(app_f)
    if search_f: q += " AND (event_type LIKE ? OR username LIKE ? OR details LIKE ?)"; params += [f"%{search_f}%",f"%{search_f}%",f"%{search_f}%"]
    q += " ORDER BY id DESC LIMIT 300"
    conn = get_db()
    logs = conn.execute(q, params).fetchall()
    total      = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    success_c  = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE status='Success'").fetchone()[0]
    failed_c   = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE status='Failed'").fetchone()[0]
    captcha_c  = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE protocol='CAPTCHA'").fetchone()[0]
    sms_c      = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE protocol='SMS OTP'").fetchone()[0]
    conn.close()

    proto_badge = {
        "Local":         "badge-muted",
        "MFA":           "badge-info",
        "Google OAuth":  "badge-cyan",
        "OAuth2":        "badge-oauth",
        "SAML":          "badge-saml",
        "App":           "badge-success",
        "CAPTCHA":       "badge-warn",
        "SMS OTP":       "badge-info",
        "Authorization": "badge-danger",
    }
    rows_html = ""
    for lg in logs:
        ts = lg["timestamp"][:16].replace("T"," ") if lg["timestamp"] else ""
        sc = "badge-success" if lg["status"]=="Success" else "badge-danger"
        pc = proto_badge.get(lg["protocol"],"badge-muted")
        rows_html += f"""<tr>
          <td style="font-size:11px;color:var(--muted);white-space:nowrap">{ts}</td>
          <td style="font-weight:600;font-size:12px">{lg['username']}</td>
          <td style="font-size:12px">{lg['event_type']}</td>
          <td><span class="badge-ok badge-muted" style="font-size:10px">{lg['app_name']}</span></td>
          <td><span class="badge-ok {pc}" style="font-size:10px">{lg['protocol']}</span></td>
          <td><span class="badge-ok {sc}" style="font-size:10px">{lg['status']}</span></td>
          <td style="font-size:11px;color:var(--muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{lg['details']}</td>
        </tr>"""

    all_protos = ["Local","MFA","Google OAuth","OAuth2","SAML","App","CAPTCHA","SMS OTP","Authorization"]
    proto_opts = '<option value="">All Protocols</option>' + "".join(
        f'<option value="{p}" {"selected" if p==proto_f else ""}>{p}</option>'
        for p in all_protos)
    status_opts = '<option value="">All Status</option>' + "".join(
        f'<option value="{s}" {"selected" if s==status_f else ""}>{s}</option>'
        for s in ["Success","Failed"])
    app_opts = '<option value="">All Apps</option>' + "".join(
        f'<option value="{a}" {"selected" if a==app_f else ""}>{a}</option>'
        for a in ["OneKey","E-Learning","Digital Library","Registration","Faculty Portal"])

    content = f"""
    <div style="margin-bottom:22px;display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
      <div>
        <div class="section-title">Audit Center</div>
        <div class="section-sub">Security event log — all protocols, CAPTCHA, SMS OTP, authorization, and authentication events</div>
      </div>
    </div>
    <div class="row-ok" style="display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px">
      <div class="stat-card"><div class="stat-value">{total}</div><div class="stat-label">Total Events</div></div>
      <div class="stat-card"><div class="stat-value text-em">{success_c}</div><div class="stat-label">Successful</div></div>
      <div class="stat-card"><div class="stat-value" style="color:#ef4444">{failed_c}</div><div class="stat-label">Failed</div></div>
      <div class="stat-card"><div class="stat-value" style="color:#fbbf24">{captcha_c}</div><div class="stat-label">CAPTCHA Events</div></div>
      <div class="stat-card"><div class="stat-value text-cy">{sms_c}</div><div class="stat-label">SMS OTP Events</div></div>
    </div>
    <div class="card-ok card-ok-pad" style="margin-bottom:16px">
      <div style="font-size:12px;font-weight:700;color:var(--muted);margin-bottom:10px">Protocol Legend</div>
      <div style="display:flex;flex-wrap:wrap;gap:8px">
        <span class="badge-ok badge-muted">Local</span>
        <span class="badge-ok badge-info">MFA</span>
        <span class="badge-ok badge-cyan">Google OAuth</span>
        <span class="badge-ok badge-oauth">OAuth2</span>
        <span class="badge-ok badge-saml">SAML</span>
        <span class="badge-ok badge-success">App</span>
        <span class="badge-ok badge-warn">CAPTCHA</span>
        <span class="badge-ok badge-info">SMS OTP</span>
        <span class="badge-ok badge-danger">Authorization</span>
      </div>
    </div>
    <div class="card-ok card-ok-pad">
      <form method="GET">
        <div class="filter-row" style="margin-bottom:16px">
          <input name="q" value="{search_f}" placeholder="Search events, users, details...">
          <select name="protocol">{proto_opts}</select>
          <select name="status">{status_opts}</select>
          <select name="app">{app_opts}</select>
          <button type="submit" class="btn-ok btn-cyan btn-sm-ok">Filter</button>
          <a href="/audit" class="btn-ok btn-muted btn-sm-ok">Clear</a>
        </div>
      </form>
      <div class="table-wrap">
        <table class="ok-table">
          <thead><tr><th>Timestamp</th><th>User</th><th>Event</th><th>App</th><th>Protocol</th><th>Status</th><th>Details</th></tr></thead>
          <tbody>{rows_html or '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:30px">No events found.</td></tr>'}</tbody>
        </table>
      </div>
    </div>"""
    return render_dash(content, "audit", "Audit Center")

# ── MFA SETUP ROUTE (for seeded users who need to scan QR) ────────────────────

@app.route("/mfa/setup", methods=["GET","POST"])
def mfa_setup():
    """Show MFA QR code after password verification — for seeded local users."""
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=? AND auth_provider='local'", (username,)).fetchone()
        conn.close()
        if user and bcrypt.check_password_hash(user["password_hash"], password):
            sec = user["mfa_secret"]
            if not sec:
                return auth_page("""<h2>No MFA Secret</h2><p class="sub">This account has no MFA secret configured. Contact an administrator.</p>
                <a href="/login" class="btn-primary-ok" style="display:block;text-align:center;text-decoration:none;margin-top:16px">Back to Login</a>""", "MFA Setup")
            totp = pyotp.TOTP(sec)
            uri  = totp.provisioning_uri(name=user["email"] or username, issuer_name="OneKey University Portal")
            img  = qrcode.make(uri)
            buf  = io.BytesIO(); img.save(buf,"PNG")
            qr64 = base64.b64encode(buf.getvalue()).decode()
            content = f"""
            <h2>MFA Setup</h2>
            <p class="sub">Scan this QR code with Google Authenticator for <strong>{username}</strong>.</p>
            <div style="text-align:center;margin:20px 0">
              <img src="data:image/png;base64,{qr64}" style="width:180px;border-radius:8px;border:4px solid #fff">
            </div>
            <div style="background:rgba(255,255,255,0.05);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:20px">
              <div style="font-size:11px;color:var(--muted);margin-bottom:4px">Manual key</div>
              <div style="font-family:monospace;color:var(--emerald);font-size:13px;word-break:break-all">{sec}</div>
            </div>
            <a href="/login" class="btn-primary-ok" style="display:block;text-align:center;text-decoration:none">Continue to Sign In</a>"""
            return auth_page(content, "MFA Setup")
        return auth_page("""<h2>MFA Setup</h2><p class="sub" style="color:#fca5a5">Invalid credentials. Please try again.</p>
        <a href="/mfa/setup" class="btn-primary-ok" style="display:block;text-align:center;text-decoration:none;margin-top:16px">Try Again</a>""", "MFA Setup")

    content = """
    <h2>MFA Setup</h2>
    <p class="sub">Enter your username and password to view your MFA QR code.</p>
    <form method="POST" style="display:block">
      <div class="form-group"><label>Username</label><input name="username" placeholder="e.g. faculty1" required autofocus></div>
      <div class="form-group"><label>Password</label><input type="password" name="password" placeholder="Your password" required></div>
      <button type="submit" class="btn-primary-ok">Show MFA QR Code</button>
    </form>
    <div class="auth-link"><a href="/login">Back to sign in</a></div>"""
    return auth_page(content, "MFA Setup")

# ══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def err_404(e):
    if "user" in session:
        content = """<div style="max-width:420px;margin:80px auto;text-align:center">
          <div style="font-size:72px;font-weight:900;color:#e2e8f0;margin-bottom:10px">404</div>
          <h2 class="section-title" style="margin-bottom:8px">Page Not Found</h2>
          <p style="color:var(--muted);margin-bottom:20px">The page you requested does not exist.</p>
          <a href="/dashboard" class="btn-ok btn-emerald">Return to Dashboard</a></div>"""
        return render_dash(content, "dashboard", "Not Found"), 404
    return auth_page("""<h2>404</h2><p class="sub">Page not found.</p><a href="/login" class="btn-primary-ok" style="display:block;text-align:center;text-decoration:none">Back to Login</a>"""), 404

@app.errorhandler(500)
def err_500(e):
    if "user" in session:
        content = """<div style="max-width:420px;margin:80px auto;text-align:center">
          <div style="font-size:72px;font-weight:900;color:#e2e8f0;margin-bottom:10px">500</div>
          <h2 class="section-title" style="margin-bottom:8px">Something Went Wrong</h2>
          <p style="color:var(--muted);margin-bottom:20px">An internal error occurred. Please try again.</p>
          <a href="/dashboard" class="btn-ok btn-emerald">Return to Dashboard</a></div>"""
        return render_dash(content, "dashboard", "Error"), 500
    return auth_page("""<h2>Error</h2><p class="sub">Something went wrong. Please try again.</p><a href="/login" class="btn-primary-ok" style="display:block;text-align:center;text-decoration:none">Back to Login</a>"""), 500

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    PORT = 5050

    if os.path.exists("localhost.pem") and os.path.exists("localhost-key.pem"):
        ssl_ctx = ("localhost.pem", "localhost-key.pem")
        ssl_label = "mkcert trusted certificate"
    else:
        ssl_ctx = "adhoc"
        ssl_label = "temporary Flask HTTPS certificate"

    print("\n" + "=" * 60)
    print("  OneKey University Portal — SSO Platform")
    print("=" * 60)
    print("  IMPORTANT: OneKey is now running on a separate port")
    print("  Open this exact URL:")
    print(f"  https://localhost:{PORT}/login")
    print(f"  SSL: {ssl_label}")
    print("=" * 60 + "\n")

    app.run(
        host="localhost",
        port=PORT,
        debug=False,
        ssl_context=ssl_ctx
    )