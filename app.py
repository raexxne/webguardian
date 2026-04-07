from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, jsonify, send_from_directory
from flask_wtf.csrf import CSRFProtect, CSRFError
import pymysql
import requests
import csv
import secrets
from dotenv import load_dotenv
import os
import re
import json
from scanner import run_zap_scan
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.pdfgen import canvas as rl_canvas

# Flask configuration
load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set in environment variables")

app.secret_key = SECRET_KEY

# CSRF protection
app.config["WTF_CSRF_ENABLED"] = True
app.config["WTF_CSRF_TIME_LIMIT"] = 3600   # 1 hour

csrf = CSRFProtect(app)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.path == url_for("execute_scan") or request.is_json:
        return jsonify({
            "success": False,
            "error": f"CSRF validation failed: {e.description}"
        }), 400

    flash(f"Security validation failed: {e.description}", "danger")
    return redirect(request.referrer or url_for("login"))

# Session & cookie hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # JS can't read cookies
    SESSION_COOKIE_SAMESITE="Lax",     # reduce CSRF
    # Set True only if you use HTTPS (production)
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",      # change to True in HTTPS production
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=True,
)

@app.after_request
def add_security_headers(response):
    # Prevent back-button showing old dashboard pages
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    # Basic security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

from flask_mail import Mail, Message

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")

app.config["MAIL_DEFAULT_SENDER"] = ("Web Guardian", app.config["MAIL_USERNAME"])

mail = Mail(app)

# ===== File Upload Settings =====

# PDF uploads
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Profile images
IMAGE_FOLDER = os.path.join('static', 'images')
os.makedirs(IMAGE_FOLDER, exist_ok=True)

# Allowed types
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_PDF = {'pdf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['IMAGE_FOLDER'] = IMAGE_FOLDER

def is_strong_password(password):
    return (
        len(password) >= 6
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[^A-Za-z0-9]", password)
    )

def password_is_hashed(stored_password):
    return isinstance(stored_password, str) and (
        stored_password.startswith("scrypt:")
        or stored_password.startswith("pbkdf2:")
    )

def hash_password(password):
    return generate_password_hash(password)

def verify_password(stored_password, provided_password):
    if not stored_password:
        return False

    if not password_is_hashed(stored_password):
        return False

    return check_password_hash(stored_password, provided_password)

# Database connection
def get_db_connection():
    return pymysql.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        database=os.environ.get("DB_NAME"),
        cursorclass=pymysql.cursors.DictCursor
    )

def send_otp_email(to_email, otp):
    subject = f"Web Guardian OTP Code: {otp}"

    msg = Message(subject=subject, recipients=[to_email])
    msg.body = f"""Your OTP code is: {otp}

This OTP expires in 10 minutes.

If you did not request this, ignore this email.
"""
    mail.send(msg)

# Helper function
def allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_pdf(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_PDF

# Login decorator
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))

            # Check user still exists + active
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT role, status FROM users WHERE id=%s", (session["user_id"],))
                    user = cursor.fetchone()
            finally:
                conn.close()

            if not user or user.get("status") != "active":
                session.clear()
                flash("Session expired or account inactive. Please login again.", "warning")
                return redirect(url_for("login"))

            if role and user.get("role") != role:
                flash("You don't have permission to access this page.", "warning")
                return redirect(url_for("dashboard"))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def zap_is_running():
    try:
        zap_api_key = os.environ.get("ZAP_API_KEY")
        if not zap_api_key:
            raise RuntimeError("ZAP_API_KEY is not set")

        response = requests.get(
            "http://127.0.0.1:8080/JSON/core/view/version/",
            params={"apikey": zap_api_key},
            timeout=5
        )

        print("ZAP health check status:", response.status_code)
        print("ZAP health check body:", response.text[:300])

        return response.status_code == 200

    except Exception as e:
        print(f"ZAP connection check failed: {e}")
        return False

def generate_otp():
    return str(secrets.randbelow(900000) + 100000)

def save_reset_otp(user_id, otp, minutes=10):
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("""
            UPDATE users
            SET reset_otp=%s, otp_expiry=%s
            WHERE id=%s
        """, (otp, datetime.now() + timedelta(minutes=minutes), user_id))
    conn.commit()
    conn.close()

# ===== NEW HELPER: Summarize ZAP JSON results =====
def summarize_from_run_zap_scan(results_json: str):
    try:
        items = json.loads(results_json) if results_json else []
        if not isinstance(items, list):
            items = []
    except Exception:
        items = []

    high = sum(1 for v in items if (v.get("risk") or "").lower() == "high")
    medium = sum(1 for v in items if (v.get("risk") or "").lower() == "medium")
    low = sum(1 for v in items if (v.get("risk") or "").lower() == "low")

    if high > 0:
        overall = "High"
    elif medium > 0:
        overall = "Medium"
    elif low > 0:
        overall = "Low"
    else:
        overall = "None"

    return high, medium, low, overall


def get_plain_language_details(vuln_name, risk, description=""):
    name = (vuln_name or "").lower()
    risk = (risk or "").title()
    description = (description or "").lower()

    # Default text by risk
    default_what = "The scan found a security weakness on this website. If it is not fixed, attackers may have a chance to misuse the system."
    default_impact = {
        "High": "This issue may lead to serious problems such as data breach, account compromise, or service disruption.",
        "Medium": "This issue may weaken the website security and could be abused if combined with other weaknesses.",
        "Low": "This issue is less critical, but it still shows that the website security can be improved."
    }.get(risk, "This issue may affect the security of the website if ignored.")

    default_action = {
        "High": "Send this issue to the IT team immediately, apply the fix as soon as possible, and run another scan after fixing.",
        "Medium": "Plan a fix in the next maintenance cycle and test the website again after the update.",
        "Low": "Review and improve this issue when possible, then re-scan to confirm the improvement."
    }.get(risk, "Review the issue, apply the proper fix, and re-scan the website.")

    # Specific explanations
    if "personally identifiable information" in name or "pii" in name:
        return {
            "what_this_means": "Sensitive personal information may be visible in the website response. This means private user data could be exposed to unauthorized people.",
            "business_impact": "This may cause privacy breach, legal or compliance issues, and loss of user trust in the website.",
            "recommended_action": "Remove or hide sensitive personal data from the response, restrict access properly, and test again after fixing."
        }

    if "sql injection" in name or "sql" in name:
        return {
            "what_this_means": "The website may be accepting unsafe input. An attacker could try to read, change, or delete data in the database.",
            "business_impact": "This may lead to stolen records, changed data, system damage, or full database compromise.",
            "recommended_action": "Validate all user input, use parameterized queries, and re-scan after the database-related fix is applied."
        }

    if "cross site scripting" in name or "xss" in name:
        return {
            "what_this_means": "The website may allow malicious script code to run in a user's browser. This can affect visitors who open the page.",
            "business_impact": "This may lead to stolen session data, fake page content, or misuse of user accounts.",
            "recommended_action": "Sanitize and encode user input/output properly, apply the fix to affected pages, and test again."
        }

    if "csrf" in name:
        return {
            "what_this_means": "The website may not be properly checking whether a request really comes from the correct user action.",
            "business_impact": "Attackers may trick logged-in users into performing unwanted actions without their knowledge.",
            "recommended_action": "Use CSRF protection tokens on sensitive forms and requests, then re-test the affected functions."
        }

    if "authentication" in name or "login" in name or "password" in name:
        return {
            "what_this_means": "The login or account protection may be weak, which can make unauthorized access easier.",
            "business_impact": "This may allow attackers to access user accounts, admin functions, or sensitive information.",
            "recommended_action": "Strengthen authentication controls, review password handling, and test the login flow again."
        }

    if "cookie" in name:
        return {
            "what_this_means": "The website cookies may not be protected strongly enough. This can make session data easier to steal or misuse.",
            "business_impact": "Weak cookie protection may increase the risk of account hijacking or unauthorized access.",
            "recommended_action": "Set secure cookie attributes such as HttpOnly, Secure, and SameSite where needed, then test again."
        }

    if "x-frame-options" in name or "clickjacking" in name:
        return {
            "what_this_means": "The website may be allowed to load inside another page or frame, which can be abused to trick users into clicking hidden content.",
            "business_impact": "This may lead to unwanted user actions, fake interactions, or misuse of sensitive functions.",
            "recommended_action": "Add proper anti-framing protection such as X-Frame-Options or CSP frame-ancestors, then re-scan."
        }

    if "content security policy" in name or "csp" in name:
        return {
            "what_this_means": "The website may not have strong browser rules to control which scripts and content are allowed to run.",
            "business_impact": "This can increase the impact of script injection and other browser-based attacks.",
            "recommended_action": "Define a proper Content Security Policy and test carefully to make sure only trusted content is allowed."
        }

    if "strict-transport-security" in name or "hsts" in name:
        return {
            "what_this_means": "The website may not be forcing secure HTTPS connections strongly enough.",
            "business_impact": "Users may be more exposed to insecure connections or man-in-the-middle attacks.",
            "recommended_action": "Enable HTTPS properly and add HSTS so browsers always use secure connections."
        }

    if "directory browsing" in name:
        return {
            "what_this_means": "The server may be showing a list of files or folders that should not be openly visible.",
            "business_impact": "Attackers may learn sensitive file names, system structure, or download files they should not access.",
            "recommended_action": "Disable directory listing on the server and restrict access to sensitive folders."
        }

    if "information disclosure" in name or "server leaks" in name or "stack trace" in name:
        return {
            "what_this_means": "The website may be revealing system or application details that should normally stay hidden.",
            "business_impact": "Attackers may use this extra information to plan more targeted attacks against the website.",
            "recommended_action": "Hide unnecessary technical details from responses and error messages, then run another scan."
        }

    return {
        "what_this_means": default_what,
        "business_impact": default_impact,
        "recommended_action": default_action
    }

def extract_safe_evidence_details(item, limit=5):
    evidence = []

    if isinstance(item.get("evidence_details"), list):
        for entry in item["evidence_details"]:
            if not isinstance(entry, dict):
                continue

            label = str(entry.get("label") or "").strip()
            value = str(entry.get("value") or "").strip()

            if not label or not value:
                continue

            evidence.append({
                "label": label[:60],
                "value": value[:400]
            })

    return evidence[:limit]

# ===== Notification Functions =====
def add_notification(user_id, message, action_url=None):
    """Add a notification for a user"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO notifications (user_id, message, action_url, created_at, is_read)
                VALUES (%s, %s, %s, NOW(), 0)
            """, (user_id, message, action_url))
            conn.commit()
            return True
    except Exception as e:
        print(f"ERROR in add_notification: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def get_notifications(user_id):
    """Get latest notifications for a user"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, user_id, message, action_url, created_at, is_read
                FROM notifications
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT 10
            """, (user_id,))
            return cursor.fetchall()
    except Exception as e:
        print(f"ERROR in get_notifications: {e}")
        return []
    finally:
        conn.close()


def get_unread_notification_count(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*) AS total
                FROM notifications
                WHERE user_id = %s AND is_read = 0
            """, (user_id,))
            row = cursor.fetchone()
            return row["total"] if row else 0
    except Exception as e:
        print(f"ERROR in get_unread_notification_count: {e}")
        return 0
    finally:
        conn.close()


def mark_notifications_as_read(user_id):
    """Mark all notifications as read for a user"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE notifications
                SET is_read = 1
                WHERE user_id = %s
            """, (user_id,))
            conn.commit()
    except Exception as e:
        print(f"ERROR marking notifications as read: {e}")
    finally:
        conn.close()

# ===== Context Processor for Notifications =====
@app.context_processor
def inject_notifications():
    if 'user_id' in session:
        notifications = get_notifications(session['user_id'])
        unread_count = get_unread_notification_count(session['user_id'])
        return dict(notifications=notifications, unread_count=unread_count)
    return dict(notifications=[], unread_count=0)

# ===== ROUTES =====

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# ===== LOGIN & PASSWORD RESET =====
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or "").strip().lower()
        password = request.form.get('password') or ""

        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()
        conn.close()

        valid_login = False

        if user:
            if user.get("status") != "active":
                flash("Your account is inactive. Please contact admin.", "warning")
                return render_template('login.html')

        stored_password = user.get("password") or ""

        if not password_is_hashed(stored_password):
            flash("Your password needs to be reset before you can log in.", "warning")
            return redirect(url_for("forgot_password"))

        valid_login = verify_password(stored_password, password)

        if valid_login:
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['name'] = user['name']
            session['role'] = user['role']
            session['profile_pic'] = user['photo'] if user['photo'] else 'default.jpg'

            flash(f"Welcome, {user['name']}!", "success")
            return redirect(url_for('dashboard'))

        flash("Invalid email or password.", "danger")

    return render_template('login.html')

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        # basic validation
        if not email:
            flash("Please enter your email.", "danger")
            return redirect(url_for("forgot_password"))

        # find user
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, email FROM users WHERE LOWER(email)=%s", (email,))
            user = cursor.fetchone()
        conn.close()

        if user:
            otp = generate_otp()
            save_reset_otp(user["id"], otp, minutes=10)

            try:
                send_otp_email(user["email"], otp)
            except Exception as e:
                print("Email send failed:", e)

        session["reset_email"] = email
        session.pop("otp_verified", None)

        flash("If the account exists, an OTP has been sent to the email address.", "info")
        return redirect(url_for("verify_otp"))
    
    return render_template("forgot_password.html")      

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = session.get("reset_email")
    if not email:
        flash("Session expired. Please request OTP again.", "warning")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        otp_input = (request.form.get("otp") or "").strip()

        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, reset_otp, otp_expiry
                FROM users
                WHERE LOWER(email)=%s
            """, (email.lower(),))
            user = cursor.fetchone()
        conn.close()

        if (
            not user
            or not user.get("reset_otp")
            or (user.get("otp_expiry") and datetime.now() > user["otp_expiry"])
            or otp_input != str(user["reset_otp"])
        ):
            flash("The OTP is invalid or expired. Please try again.", "danger")
            return redirect(url_for("verify_otp"))

        session["otp_verified"] = True
        return redirect(url_for("reset_password"))

    return render_template("verify_otp.html", email=email)

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    email = session.get("reset_email")
    if not email or not session.get("otp_verified"):
        flash("Please verify OTP first.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_pw = (request.form.get("password") or "").strip()
        confirm = (request.form.get("confirm_password") or "").strip()

        if new_pw != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("reset_password"))

        if not is_strong_password(new_pw):
            flash("Password must be at least 6 characters and include uppercase, lowercase, number, and special character.", "danger")
            return redirect(url_for("reset_password"))

        hashed_password = hash_password(new_pw)

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users
                    SET password=%s, reset_otp=NULL, otp_expiry=NULL
                    WHERE LOWER(email)=%s
                """, (hashed_password, email.lower()))
            conn.commit()
        finally:
            conn.close()

        session.pop("reset_email", None)
        session.pop("otp_verified", None)

        flash("Password updated successfully. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    email = session.get("reset_email")
    if not email:
        return jsonify({"success": False, "message": "Session expired. Please request OTP again."}), 400

    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT id, email FROM users WHERE LOWER(email)=%s", (email.lower(),))
        user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({
            "success": True,
            "message": "If the account exists, a new OTP has been sent."
        }), 200

    otp = generate_otp()
    save_reset_otp(user["id"], otp, minutes=10)
    send_otp_email(user["email"], otp)
    return jsonify({"success": True, "message": "OTP resent."})

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    role = session.get('role')
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'manager':
        return redirect(url_for('manager_dashboard'))
    elif role == 'staff':
        return redirect(url_for('staff_dashboard'))
    else:
        session.clear()
        flash("Unknown role. Please login again.", "danger")
        return redirect(url_for('login'))

# ===== SCANNING ROUTES =====
@app.route('/scan', methods=['GET', 'POST'])
@login_required(role='staff')
def scan():
    if request.method == 'POST':
        target_url = request.form.get('target_url')

        if not target_url:
            flash("Please enter a target URL.", "danger")
            return redirect(url_for('scan'))

        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url

        return redirect(url_for('scan_loading', target_url=target_url))

    zap_available = zap_is_running()

    if not zap_available:
        print("SCAN ERROR: OWASP ZAP is not running or not reachable on 127.0.0.1:8080")

    return render_template(
        'scan.html',
        zap_available=zap_available
    )

@app.route('/scan/loading')
@login_required(role='staff')
def scan_loading():
    """Loading page while scan is in progress"""
    target_url = request.args.get('target_url')
    return render_template('scan_loading.html', target_url=target_url)

# Only staff can execute scan + save risk + counts
@app.route('/scan/execute', methods=['POST'])
@login_required(role='staff')
def execute_scan():
    try:
        data = request.get_json(silent=True) or request.form.to_dict() or {}
        target_url = (data.get("target_url") or "").strip()

        if not target_url:
            return jsonify({
                "success": False,
                "error": "Target URL is required."
            }), 400

        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url

        if not zap_is_running():
            print("SCAN ERROR: OWASP ZAP is not reachable on 127.0.0.1:8080")
            return jsonify({
                "success": False,
                "error": "Scan could not be completed. Please try again later."
            }), 503

        results_json = run_zap_scan(target_url)
        if not results_json:
            results_json = "[]"

        high_count, medium_count, low_count, overall_risk = summarize_from_run_zap_scan(results_json)

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO scans (
                        user_id, target_url, result, risk,
                        high_count, medium_count, low_count, created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                """, (
                    session["user_id"],
                    target_url,
                    results_json,
                    overall_risk,
                    high_count,
                    medium_count,
                    low_count
                ))
            conn.commit()
        finally:
            conn.close()

        return jsonify({
            "success": True,
            "redirect_url": url_for("reports")
        }), 200

    except Exception as e:
        print("ERROR in /scan/execute:", repr(e))
        return jsonify({
            "success": False,
            "error": "An error occurred while scanning. Please try again later."
        }), 500
    
@app.route('/scan/check-zap', methods=['GET'])
@login_required(role='staff')
def check_zap():
    try:
        if zap_is_running():
            return jsonify({
                "success": True,
                "message": "Scanner is ready."
            }), 200
        else:
            print("SCAN ERROR: OWASP ZAP is not reachable on 127.0.0.1:8080")
            return jsonify({
                "success": False,
                "message": "Scan cannot be started right now. Please try again later."
            }), 503
    except Exception as e:
        print("ERROR in /scan/check-zap:", repr(e))
        return jsonify({
            "success": False,
            "message": "Scan cannot be started right now. Please try again later."
        }), 500

@app.route('/scan/details/<int:scan_id>')
@login_required()
def get_scan_details(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    try:
        if session.get("role") == "staff":
            cursor.execute(
                "SELECT result FROM scans WHERE id=%s AND user_id=%s",
                (scan_id, session["user_id"])
            )
        else:
            cursor.execute("SELECT result FROM scans WHERE id=%s", (scan_id,))

        scan = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not scan:
        return jsonify({"error": "Scan not found or access denied"}), 404

    try:
        results = json.loads(scan["result"] or "[]")
        if not isinstance(results, list):
            results = []

        enriched_results = []

        for item in results:
            if not isinstance(item, dict):
                continue

            plain_info = get_plain_language_details(
                item.get("name") or item.get("alert"),
                item.get("risk"),
                item.get("description")
            )

            enriched_item = dict(item)
            enriched_item["what_this_means"] = plain_info["what_this_means"]
            enriched_item["business_impact"] = plain_info["business_impact"]
            enriched_item["recommended_action"] = plain_info["recommended_action"]

            # new real evidence
            enriched_item["evidence_details"] = extract_safe_evidence_details(item)

            enriched_results.append(enriched_item)

        return jsonify(enriched_results)

    except Exception:
        return jsonify([])

# ===== REPORTS =====
@app.route('/reports')
@login_required()
def reports():
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    try:
        # Staff: show ONLY own scans
        if session.get("role") == "staff":
            cursor.execute("""
                SELECT scans.*, users.name
                FROM scans
                JOIN users ON scans.user_id = users.id
                WHERE scans.user_id = %s
                ORDER BY scans.created_at DESC
            """, (session["user_id"],))
        else:
            # Manager/Admin: keep existing behavior (all scans)
            cursor.execute("""
                SELECT scans.*, users.name
                FROM scans
                JOIN users ON scans.user_id = users.id
                ORDER BY scans.created_at DESC
            """)
        scans = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    # parse JSON results (same as your current logic)
    for scan in scans:
        try:
            scan["parsed_result"] = json.loads(scan.get("result") or "[]")
            if not isinstance(scan["parsed_result"], list):
                scan["parsed_result"] = []
        except Exception:
            scan["parsed_result"] = []

    return render_template("reports.html", scans=scans)


@app.route('/reports/view/<int:scan_id>')
@login_required()
def view_report_detail(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    try:
        if session.get("role") == "staff":
            cursor.execute("""
                SELECT scans.*, users.name
                FROM scans
                JOIN users ON scans.user_id = users.id
                WHERE scans.id = %s AND scans.user_id = %s
            """, (scan_id, session["user_id"]))
        else:
            cursor.execute("""
                SELECT scans.*, users.name
                FROM scans
                JOIN users ON scans.user_id = users.id
                WHERE scans.id = %s
            """, (scan_id,))
        scan = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not scan:
        flash("Report not found or access denied.", "danger")
        return redirect(url_for('reports'))

    return render_template('report_detail.html', scan=scan)

# ===== ADMIN =====
@app.route('/admin')
@login_required(role='admin')
def admin_dashboard():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT id, name, email, role, photo, status
            FROM users
        """)
        users = cursor.fetchall()
    conn.close()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/add', methods=['GET', 'POST'])
@login_required(role='admin')
def add_user():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        if password != confirm_password:
            flash("Password and Confirm Password do not match.", "danger")
            return redirect(url_for('add_user'))

        if not is_strong_password(password):
            flash("Password must be at least 6 characters and include uppercase, lowercase, number, and special character.", "danger")
            return redirect(url_for('add_user'))

        hashed_password = hash_password(password)

        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                conn.close()
                flash("Email already exists.", "danger")
                return redirect(url_for('add_user'))

            cursor.execute("""
                INSERT INTO users (name, email, password, role)
                VALUES (%s, %s, %s, %s)
            """, (name, email, hashed_password, role))
            conn.commit()
        conn.close()

        flash("New user added successfully.", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('add_user.html')

@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required(role='admin')
def edit_user(user_id):
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()

        if request.method == 'POST':
            name = request.form['name'].strip()
            email = request.form['email'].strip().lower()
            password = request.form['password']
            role = request.form['role']

            cursor.execute("SELECT id FROM users WHERE email=%s AND id != %s", (email, user_id))
            existing_user = cursor.fetchone()

            if existing_user:
                conn.close()
                flash("Email already exists.", "danger")
                return redirect(url_for('edit_user', user_id=user_id))

            if password:
                if not is_strong_password(password):
                    conn.close()
                    flash("Password must be at least 6 characters and include uppercase, lowercase, number, and special character.", "danger")
                    return redirect(url_for('edit_user', user_id=user_id))

                hashed_password = hash_password(password)
                cursor.execute("""
                    UPDATE users
                    SET name=%s, email=%s, password=%s, role=%s
                    WHERE id=%s
                """, (name, email, hashed_password, role, user_id))
            else:
                cursor.execute("""
                    UPDATE users
                    SET name=%s, email=%s, role=%s
                    WHERE id=%s
                """, (name, email, role, user_id))

            conn.commit()
            conn.close()
            flash("User updated successfully.", "success")
            return redirect(url_for('admin_dashboard'))

    conn.close()
    return render_template('edit_user.html', user=user)

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@login_required(role='admin')
def delete_user(user_id):
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()
    conn.close()
    flash("User deleted successfully.", "info")
    return redirect(url_for('admin_dashboard'))

# ===== MANAGER =====
@app.route('/manager')
@login_required(role='manager')
def manager_dashboard():
    staff_id = (request.args.get("staff_id") or "").strip()

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    # Staff list (dropdown)
    cursor.execute("""
        SELECT id, name
        FROM users
        WHERE role='staff' AND status='active'
        ORDER BY name
    """)
    staff_list = cursor.fetchall()

    # Fetch scans (filter by selected staff if provided)
    if staff_id:
        cursor.execute("""
            SELECT scans.*, users.name
            FROM scans
            JOIN users ON scans.user_id = users.id
            WHERE scans.user_id = %s
            ORDER BY scans.created_at DESC
        """, (staff_id,))
    else:
        cursor.execute("""
            SELECT scans.*, users.name
            FROM scans
            JOIN users ON scans.user_id = users.id
            ORDER BY scans.created_at DESC
        """)
    scans = cursor.fetchall()

    # Tasks (keep your existing query)
    cursor.execute("""
        SELECT t.*, u.name as staff_name 
        FROM tasks t 
        JOIN users u ON t.staff_id = u.id 
        WHERE t.manager_id = %s 
        ORDER BY t.created_at DESC
    """, (session['user_id'],))
    tasks = cursor.fetchall()

    cursor.close()
    conn.close()

    # Parse JSON + compute totals EXACTLY like reports.html
    high_count = 0
    medium_count = 0
    low_count = 0

    for scan in scans:
        try:
            parsed = json.loads(scan.get("result") or "[]")
            if not isinstance(parsed, list):
                parsed = []
        except Exception:
            parsed = []
        scan["parsed_result"] = parsed

        for vuln in parsed:
            r = (vuln.get("risk") or "")
            if r == "High":
                high_count += 1
            elif r == "Medium":
                medium_count += 1
            elif r == "Low":
                low_count += 1

    total_count = high_count + medium_count + low_count

    return render_template(
        "manager_dashboard.html",
        scans=scans,
        tasks=tasks,
        staff_list=staff_list,
        selected_staff_id=int(staff_id) if staff_id.isdigit() else None,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        total_count=total_count
    )

@app.route('/manager/tasks', methods=['GET', 'POST'])
@login_required(role='manager')
def manager_tasks():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT id, name FROM users
            WHERE role='staff' AND status='active'
            ORDER BY name
        """)
        staffs = cursor.fetchall()

        if request.method == 'POST':
            target_url = request.form['target_url'].strip()
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'http://' + target_url

            staff_id = request.form['staff_id']
            description = request.form.get('description', '')

            cursor.execute("SELECT id, name, email FROM users WHERE id = %s", (staff_id,))
            staff = cursor.fetchone()

            if not staff:
                flash("Staff not found.", "danger")
                conn.close()
                return redirect(url_for('manager_tasks'))

            cursor.execute("""
                INSERT INTO tasks (target_url, staff_id, manager_id, description, status)
                VALUES (%s, %s, %s, %s, 'pending')
            """, (target_url, staff_id, session['user_id'], description))
            task_id = cursor.lastrowid

            # Add notification for staff
            message = f"New scan task assigned: {target_url}"
            if description:
                message += f" - {description}"

            action_url = url_for('staff_select_task', task_id=task_id)
            add_notification(staff_id, message, action_url)
            conn.commit()
            flash(f"Task assigned successfully to {staff['name']}.", "success")

            return redirect(url_for('manager_tasks'))

    conn.close()
    return render_template('manager_tasks.html', staffs=staffs)

@app.route('/manager/reports/delete/<int:report_id>', methods=['POST'])
@login_required(role='manager')
def delete_pdf_report(report_id):
    """
    Delete a task (PDF report) and remove the associated PDF file if it exists.
    Only the manager who owns the task is allowed to delete it.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            
            # 1) Verify that this task belongs to the logged-in manager
            cursor.execute("""
                SELECT id, pdf_path
                FROM tasks
                WHERE id = %s AND manager_id = %s
            """, (report_id, session['user_id']))
            
            task = cursor.fetchone()

            if not task:
                flash("Task not found or you do not have permission to delete it.", "danger")
                return redirect(url_for('manager_reports'))

            # 2) Delete the PDF file if it exists
            pdf_path = task.get("pdf_path")
            if pdf_path:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_path)
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print("PDF delete error:", e)

            # 3) Delete the task record from the database
            cursor.execute("""
                DELETE FROM tasks 
                WHERE id = %s AND manager_id = %s
            """, (report_id, session['user_id']))
            
            conn.commit()

        flash("Task and PDF report were successfully deleted.", "success")
        return redirect(url_for('manager_reports'))

    except Exception as e:
        conn.rollback()
        print("Database delete error:", e)
        flash("Failed to delete the task. Please try again.", "danger")
        return redirect(url_for('manager_reports'))

    finally:
        conn.close()

@app.route('/manager/reports')
@login_required(role='manager')
def manager_reports():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT s.*, u.name as scanned_by 
            FROM scans s 
            JOIN users u ON s.user_id = u.id 
            ORDER BY s.created_at DESC
        """)
        scans = cursor.fetchall()

        cursor.execute("""
    SELECT t.*, u.name AS staff_name, u.photo AS staff_photo
            FROM tasks t
            JOIN users u ON t.staff_id = u.id
            WHERE t.manager_id = %s
            ORDER BY 
                CASE 
                    WHEN t.status = 'pending' THEN 1
                    WHEN t.status = 'in_progress' THEN 2
                    WHEN t.status = 'completed' THEN 3
                END,
                t.updated_at DESC
        """, (session['user_id'],))
        pdf_reports = cursor.fetchall()
    conn.close()
    return render_template('manager_reports.html', scans=scans, pdf_reports=pdf_reports)

@app.route('/manager/progress')
@login_required(role='manager')
def manager_progress():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT t.*, u.name as staff_name, m.name as manager_name
            FROM tasks t
            JOIN users u ON t.staff_id = u.id
            JOIN users m ON t.manager_id = m.id
            WHERE t.manager_id = %s
            ORDER BY t.created_at DESC
        """, (session['user_id'],))
        tasks = cursor.fetchall()
    conn.close()
    return render_template('manager_progress.html', tasks=tasks)

# ===== STAFF =====
@app.route('/staff')
@login_required(role='staff')
def staff_dashboard():
    selected_task_id = session.get('selected_task_id')
    task = None

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if selected_task_id:
                cursor.execute("""
                    SELECT t.*, u.name AS manager_name
                    FROM tasks t
                    JOIN users u ON t.manager_id = u.id
                    WHERE t.id = %s
                      AND t.staff_id = %s
                      AND t.status = 'pending'
                    LIMIT 1
                """, (selected_task_id, session['user_id']))
                task = cursor.fetchone()

            if not task:
                cursor.execute("""
                    SELECT t.*, u.name AS manager_name
                    FROM tasks t
                    JOIN users u ON t.manager_id = u.id
                    WHERE t.staff_id = %s
                      AND t.status = 'pending'
                    ORDER BY t.created_at DESC
                    LIMIT 1
                """, (session['user_id'],))
                task = cursor.fetchone()

                if task:
                    session['selected_task_id'] = task['id']
                else:
                    session.pop('selected_task_id', None)
    finally:
        conn.close()

    return render_template('staff_dashboard.html', task=task if task else {})

@app.route('/staff/select-task/<int:task_id>')
@login_required(role='staff')
def staff_select_task(task_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id
                FROM tasks
                WHERE id = %s AND staff_id = %s AND status = 'pending'
            """, (task_id, session['user_id']))
            task = cursor.fetchone()

        if not task:
            flash("Task not found or already completed.", "danger")
            return redirect(url_for('staff_dashboard'))

        session['selected_task_id'] = task_id
        flash("Task selected successfully.", "success")
        return redirect(url_for('staff_dashboard'))

    finally:
        conn.close()

@app.route('/staff/upload-report/<int:task_id>', methods=['POST'])
@login_required(role='staff')
def upload_report(task_id):
    if 'report_pdf' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('staff_dashboard'))

    file = request.files['report_pdf']
    if not file or file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('staff_dashboard'))

    if not allowed_pdf(file.filename):
        flash('Only PDF files are allowed', 'danger')
        return redirect(url_for('staff_dashboard'))

    if file.mimetype not in ['application/pdf', 'application/x-pdf']:
        flash('Invalid PDF file.', 'danger')
        return redirect(url_for('staff_dashboard'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT t.*, u.name as manager_name, u.id as manager_id
                FROM tasks t
                JOIN users u ON t.manager_id = u.id
                WHERE t.id = %s AND t.staff_id = %s AND t.status = 'pending'
            """, (task_id, session['user_id']))
            task = cursor.fetchone()

            if not task:
                flash("Task not found or you don't have permission.", "danger")
                return redirect(url_for('staff_dashboard'))

            filename = secure_filename(
                f"report_{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            )
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            cursor.execute("""
                UPDATE tasks
                SET status = 'completed',
                    pdf_path = %s,
                    updated_at = NOW()
                WHERE id = %s
            """, (filename, task_id))

            if session.get('selected_task_id') == task_id:
                session.pop('selected_task_id', None)

            message = f"{session['name']} has submitted a PDF report for task: {task['target_url']}"
            action_url = url_for('view_pdf', filename=filename)
            add_notification(task['manager_id'], message, action_url)

        conn.commit()
        flash("Report sent to manager successfully.", "success")
    finally:
        conn.close()

    return redirect(url_for('staff_dashboard'))

# ===== NOTIFICATIONS =====
@app.route('/notifications/read', methods=['POST'])
@login_required()
def mark_notifications_read():
    user_id = session['user_id']
    mark_notifications_as_read(user_id)
    flash("All notifications marked as read.", "success")
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/notifications/open/<int:notification_id>')
@login_required()
def open_notification(notification_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT *
                FROM notifications
                WHERE id = %s AND user_id = %s
            """, (notification_id, session['user_id']))
            notification = cursor.fetchone()

            if not notification:
                flash("Notification not found or access denied.", "danger")
                return redirect(url_for('dashboard'))

            cursor.execute("""
                UPDATE notifications
                SET is_read = 1
                WHERE id = %s AND user_id = %s
            """, (notification_id, session['user_id']))
            conn.commit()

        action_url = notification.get("action_url")
        if action_url:
            return redirect(action_url)

        flash("This notification has no linked page.", "warning")
        return redirect(url_for('dashboard'))

    finally:
        conn.close()


@app.route('/notifications/delete/<int:notification_id>', methods=['POST'])
@login_required()
def delete_notification(notification_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                DELETE FROM notifications
                WHERE id = %s AND user_id = %s
            """, (notification_id, session['user_id']))
            conn.commit()

        unread_count = get_unread_notification_count(session['user_id'])

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                "success": True,
                "unread_count": unread_count
            })

        flash("Notification deleted.", "success")
    except Exception as e:
        print(f"ERROR deleting notification: {e}")

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                "success": False,
                "error": "Failed to delete notification."
            }), 500

        flash("Failed to delete notification.", "danger")
    finally:
        conn.close()

    return redirect(request.referrer or url_for('dashboard'))

# ===== PROFILE =====
@app.route('/profile', methods=['GET', 'POST'])
@login_required()
def profile():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
            user = cursor.fetchone()

            if request.method == 'POST':
                name = (request.form.get('name') or "").strip()
                email = (request.form.get('email') or "").strip().lower()
                password = (request.form.get('password') or "").strip()
                photo = user['photo']

                if 'photo' in request.files:
                    file = request.files['photo']
                    if file and allowed_image(file.filename):
                        ext = file.filename.rsplit('.', 1)[1].lower()
                        filename = f"{secrets.token_hex(16)}.{ext}"
                        file_path = os.path.join(app.config['IMAGE_FOLDER'], filename)
                        file.save(file_path)
                        photo = filename

                # if password field is filled, hash it
                if password:
                    if not is_strong_password(password):
                        flash("Password must be at least 6 characters and include uppercase, lowercase, number, and special character.", "danger")
                        return redirect(url_for('profile'))

                    hashed_password = hash_password(password)

                    cursor.execute("""
                        SELECT id FROM users
                        WHERE email = %s AND id != %s
                    """, (email, session['user_id']))
                    existing_user = cursor.fetchone()

                    if existing_user:
                        flash("Email already exists.", "danger")
                        return redirect(url_for('profile'))

                    cursor.execute("""
                        UPDATE users
                        SET name=%s, email=%s, password=%s, photo=%s
                        WHERE id=%s
                    """, (name, email, hashed_password, photo, session['user_id']))
                else:
                    # if password field is blank, keep old password
                    cursor.execute("""
                        UPDATE users
                        SET name=%s, email=%s, photo=%s
                        WHERE id=%s
                    """, (name, email, photo, session['user_id']))

                conn.commit()

                session['name'] = name
                session['email'] = email
                session['profile_pic'] = photo if photo else 'default.jpg'

                flash("Profile updated successfully!", "success")
                return redirect(url_for('profile'))

    finally:
        conn.close()

    return render_template('profile.html', user=user)

# ===== DOWNLOAD REPORTS =====
@app.route('/reports/download')
@login_required()
def download_report():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if session['role'] == 'staff':
            cursor.execute("""
                SELECT scans.id, scans.target_url, scans.result, scans.risk, scans.created_at
                FROM scans 
                WHERE scans.user_id = %s
                ORDER BY scans.created_at DESC
            """, (session['user_id'],))
        else:
            cursor.execute("""
                SELECT scans.id, users.name, scans.target_url, scans.result, scans.risk, scans.created_at
                FROM scans JOIN users ON scans.user_id = users.id
                ORDER BY scans.created_at DESC
            """)
        rows = cursor.fetchall()
    conn.close()

    def generate():
        import io
        data = io.StringIO()
        writer = csv.writer(data)

        if session['role'] == 'staff':
            writer.writerow(('ID', 'Target URL', 'Result', 'Risk', 'Created At'))
        else:
            writer.writerow(('ID', 'User', 'Target URL', 'Result', 'Risk', 'Created At'))

        yield data.getvalue()
        data.seek(0)
        data.truncate(0)

        for row in rows:
            if session['role'] == 'staff':
                writer.writerow((row['id'], row['target_url'], row['result'], row['risk'], row['created_at']))
            else:
                writer.writerow((row['id'], row.get('name', ''), row['target_url'], row['result'], row['risk'], row['created_at']))
            yield data.getvalue()
            data.seek(0)
            data.truncate(0)

    return Response(generate(), mimetype='text/csv',
                    headers={"Content-Disposition": "attachment;filename=scan_reports.csv"})

@app.route('/reports/download_pdf')
@login_required()
def download_pdf():
    flash("Please download PDF from a specific scan report using the PDF button.", "info")
    return redirect(url_for('reports'))

# ===== OTHER ROUTES =====
@app.route('/reports/send')
@login_required(role='staff')
def send_report_to_manager():
    flash("Security scan report has been sent to manager successfully.", "success")
    return redirect(url_for('reports'))

@app.route('/reports/delete/<int:scan_id>', methods=['POST'])
@login_required()
def delete_scan(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    try:
        # Staff can delete ONLY their own scan
        if session.get("role") == "staff":
            cursor.execute("DELETE FROM scans WHERE id=%s AND user_id=%s", (scan_id, session["user_id"]))
        else:
            # Manager/Admin: can delete any scan (optional behavior)
            cursor.execute("DELETE FROM scans WHERE id=%s", (scan_id,))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    flash("Scan report deleted successfully.", "info")
    return redirect(url_for('reports'))

@app.route('/scan/pdf/<int:scan_id>')
@login_required()
def download_scan_pdf(scan_id):
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if session.get("role") == "staff":
            cursor.execute("""
                SELECT scans.*, users.name
                FROM scans
                JOIN users ON scans.user_id = users.id
                WHERE scans.id = %s AND scans.user_id = %s
            """, (scan_id, session["user_id"]))
        else:
            cursor.execute("""
                SELECT scans.*, users.name
                FROM scans
                JOIN users ON scans.user_id = users.id
                WHERE scans.id = %s
            """, (scan_id,))
        scan = cursor.fetchone()
    conn.close()

    if not scan:
        flash("Scan not found.", "danger")
        return redirect(url_for("reports"))

    # =========================
    # Helper functions
    # =========================
    def parse_json_safe(raw):
        try:
            return json.loads(raw or "[]")
        except Exception:
            return []

    def normalize_vulns(obj):
        if isinstance(obj, list):
            return [x for x in obj if isinstance(x, dict)]

        if isinstance(obj, dict):
            for key in ("alerts", "results", "vulnerabilities", "items", "data"):
                if isinstance(obj.get(key), list):
                    return [x for x in obj.get(key) if isinstance(x, dict)]

            if isinstance(obj.get("site"), list):
                all_alerts = []
                for site in obj["site"]:
                    if isinstance(site, dict) and isinstance(site.get("alerts"), list):
                        all_alerts.extend([x for x in site["alerts"] if isinstance(x, dict)])
                return all_alerts

        return []

    def extract_risk(v):
        candidates = [
            v.get("risk"), v.get("severity"), v.get("risk_level"),
            v.get("riskLevel"), v.get("riskdesc"), v.get("riskDesc")
        ]

        for c in candidates:
            if not c:
                continue
            s = str(c).strip().lower()
            if "high" in s:
                return "High"
            if "medium" in s:
                return "Medium"
            if "low" in s:
                return "Low"
            if "info" in s or "informational" in s:
                return "Low"

        return "Low"

    def safe_int(x):
        try:
            return int(x)
        except Exception:
            return 0

    def clean_text(t, strip_tags=True):
        t = str(t or "")
        if strip_tags:
            t = re.sub(r"<[^>]*>", "", t)
        t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return t

    def clip(t, n=250, strip_tags=True):
        t = str(t or "")
        if strip_tags:
            t = re.sub(r"<[^>]*>", "", t)
        t = re.sub(r"\s+", " ", t).strip()
        if len(t) <= n:
            return t
        return t[:n].rstrip() + "..."

    def pick_name(v):
        return str(v.get("name") or v.get("alert") or v.get("title") or "Vulnerability")

    def pick_desc(v):
        return str(v.get("description") or v.get("desc") or v.get("message") or "No description available.")

    def pick_solution(v):
        return str(v.get("solution") or v.get("recommendation") or v.get("remediation") or "No remediation guidance provided.")

    def pick_reference(v):
        ref = v.get("reference") or v.get("references") or v.get("url") or ""
        return clip(ref, 180)

    def pick_cwe(v):
        cwe = v.get("cweid") or v.get("cwe") or v.get("cweId")
        return str(cwe) if cwe else "N/A"

    def pick_wasc(v):
        wasc = v.get("wascid") or v.get("wasc") or v.get("wascId")
        return str(wasc) if wasc else "N/A"

    def extract_evidence(v):
        evidence_lines = []

        if isinstance(v.get("evidence_details"), list):
            for item in v.get("evidence_details"):
                if not isinstance(item, dict):
                    continue
                label_txt = str(item.get("label") or "").strip()
                value_txt = str(item.get("value") or "").strip()
                if label_txt and value_txt:
                    evidence_lines.append(f"- {label_txt}: {clip(value_txt, 120)}")

        if not evidence_lines:
            raw_evidence = str(v.get("evidence") or "").strip()
            if raw_evidence:
                evidence_lines.append(f"- {clip(raw_evidence, 160)}")

        if not evidence_lines:
            evidence_lines.append("- No detailed evidence provided by the scanner.")

        return evidence_lines[:4]

    def get_risk_colors(risk):
        risk = (risk or "").lower()
        if risk == "high":
            return {
                "accent": "#B91C1C",
                "bg": "#FEF2F2",
                "pill_bg": "#FEE2E2",
                "pill_fg": "#B91C1C"
            }
        elif risk == "medium":
            return {
                "accent": "#B45309",
                "bg": "#FFFBEB",
                "pill_bg": "#FEF3C7",
                "pill_fg": "#B45309"
            }
        else:
            return {
                "accent": "#15803D",
                "bg": "#F0FDF4",
                "pill_bg": "#DCFCE7",
                "pill_fg": "#15803D"
            }

    def build_pill(text, bg_color, fg_color):
        pill_style = ParagraphStyle(
            "pill_style",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=9,
            alignment=1,
            textColor=colors.HexColor(fg_color)
        )

        pill = Table(
            [[Paragraph(text, pill_style)]],
            colWidths=[20 * mm]
        )
        pill.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg_color)),
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor(bg_color)),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return pill

    def metric_card(title_txt, value_txt, accent_hex, soft_hex):
        card = Table([
            [Paragraph(title_txt, metric_label_style)],
            [Paragraph(value_txt, metric_value_style)]
        ], colWidths=[42 * mm])

        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(soft_hex)),
            ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#E2E8F0")),
            ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(accent_hex)),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return card

    def score_band(score_value):
        if score_value >= 80:
            return "Secure", "#15803D", "#DCFCE7"
        elif score_value >= 50:
            return "Moderate Risk", "#B45309", "#FEF3C7"
        else:
            return "Critical Risk", "#B91C1C", "#FEE2E2"

    # =========================
    # Parse result and compute counts
    # =========================
    raw_obj = parse_json_safe(scan.get("result"))
    vulns = normalize_vulns(raw_obj)

    high = safe_int(scan.get("high_count"))
    medium = safe_int(scan.get("medium_count"))
    low = safe_int(scan.get("low_count"))

    if (high + medium + low) == 0 and vulns:
        for v in vulns:
            risk_val = extract_risk(v)
            if risk_val == "High":
                high += 1
            elif risk_val == "Medium":
                medium += 1
            else:
                low += 1

    total_findings = high + medium + low

    score = 100 - (high * 20) - (medium * 10) - (low * 5)
    if score < 0:
        score = 0

    score_label, score_accent, score_soft = score_band(score)

    # =========================
    # Scan metadata
    # =========================
    target_url = clean_text(scan.get("target_url") or "-")
    scanned_by = clean_text(scan.get("name") or "-")

    raw_created_at = scan.get("created_at")
    display_date = "-"
    display_time = "-"

    if raw_created_at:
        try:
            malaysia_tz = ZoneInfo("Asia/Kuala_Lumpur")

            if raw_created_at.tzinfo is None:
                # Treat MySQL naive datetime as Malaysia time directly
                malaysia_time = raw_created_at.replace(tzinfo=malaysia_tz)
            else:
                malaysia_time = raw_created_at.astimezone(malaysia_tz)

            display_date = malaysia_time.strftime("%d %b %Y")
            display_time = malaysia_time.strftime("%H:%M:%S")
        except Exception:
            display_date = clean_text(str(raw_created_at))
            display_time = "-"

    # =========================
    # PDF setup
    # =========================
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=20 * mm,
        bottomMargin=14 * mm
    )

    doc.title = "Web Guardian Security Scan Report"
    doc.author = "Web Guardian"
    doc.subject = "Security Scan Report"
    doc.creator = "Web Guardian"

    styles = getSampleStyleSheet()

    cover_title_style = ParagraphStyle(
        "cover_title_style",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0F172A"),
        alignment=0,
        spaceAfter=6
    )

    cover_subtitle_style = ParagraphStyle(
        "cover_subtitle_style",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748B"),
        alignment=0,
        spaceAfter=10
    )

    section_title_style = ParagraphStyle(
        "section_title_style",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=5,
        spaceBefore=4
    )

    body_style = ParagraphStyle(
        "body_style",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#0F172A")
    )

    body_muted_style = ParagraphStyle(
        "body_muted_style",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#475569")
    )

    small_style = ParagraphStyle(
        "small_style",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.2,
        leading=10.5,
        textColor=colors.HexColor("#0F172A")
    )

    small_muted_style = ParagraphStyle(
        "small_muted_style",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#64748B")
    )

    code_style = ParagraphStyle(
        "code_style",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=11,
        textColor=colors.HexColor("#1D4ED8")
    )

    table_header_style = ParagraphStyle(
        "table_header_style",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.3,
        leading=10,
        textColor=colors.white,
        alignment=1
    )

    table_cell_style = ParagraphStyle(
        "table_cell_style",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.2,
        leading=10,
        textColor=colors.HexColor("#0F172A")
    )

    metric_label_style = ParagraphStyle(
        "metric_label_style",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#475569"),
        alignment=1
    )

    metric_value_style = ParagraphStyle(
        "metric_value_style",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=17,
        leading=20,
        textColor=colors.HexColor("#0F172A"),
        alignment=1
    )

    finding_title_style = ParagraphStyle(
        "finding_title_style",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0F172A")
    )

    sub_box_title_style = ParagraphStyle(
        "sub_box_title_style",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=11,
        textColor=colors.HexColor("#0F172A")
    )

    # =========================
    # Dynamic executive summary
    # =========================
    if total_findings == 0:
        summary_text = (
            "The Web Guardian did not identify any high, medium, or low risk findings "
            "for the scanned target at the time of testing. This result indicates a strong security "
            "posture based on the scan coverage used in this report."
        )
    else:
        summary_text = (
            f"The Web Guardian identified {total_findings} finding(s) for the target website, "
            f"consisting of {high} high risk, {medium} medium risk, and {low} low risk issue(s). "
            f"The overall security score for this scan is {score}/100, which is classified as "
            f"{score_label}. Priority should be given to resolving high and medium risk findings first."
        )

    # =========================
    # Build PDF content
    # =========================
    elements = []

    # ---- Cover / Executive page ----
    elements.append(Spacer(1, 4))
    elements.append(Paragraph("WEB GUARDIAN", cover_subtitle_style))
    elements.append(Paragraph("Security Scan Report", cover_title_style))
    elements.append(Paragraph(
        "Professional vulnerability scan summary generated from the recorded scan results.",
        cover_subtitle_style
    ))
    elements.append(Spacer(1, 6))

    top_status_box = Table([
        [Paragraph("<b>Assessment Result</b>", body_muted_style),
         Paragraph(f"<b>{score_label}</b>", ParagraphStyle(
             "status_value",
             parent=body_style,
             fontName="Helvetica-Bold",
             textColor=colors.HexColor(score_accent),
             alignment=1
         ))],
        [Paragraph("Security Score", body_muted_style),
         Paragraph(f"<b>{score}/100</b>", ParagraphStyle(
             "score_value",
             parent=body_style,
             fontName="Helvetica-Bold",
             textColor=colors.HexColor("#0F172A"),
             alignment=1
         ))],
    ], colWidths=[110 * mm, 60 * mm])

    top_status_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(score_soft)),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#E2E8F0")),
        ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(score_accent)),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    elements.append(top_status_box)
    elements.append(Spacer(1, 10))

    meta_table = Table([
        [Paragraph("<b>Target URL</b>", small_muted_style), Paragraph(target_url, code_style)],
        [Paragraph("<b>Scanned By</b>", small_muted_style), Paragraph(scanned_by, body_style)],
        [Paragraph("<b>Scan Date</b>", small_muted_style), Paragraph(display_date, body_style)],
        [Paragraph("<b>Scan Time</b>", small_muted_style), Paragraph(display_time, body_style)],
        [Paragraph("<b>Total Findings</b>", small_muted_style), Paragraph(str(total_findings), body_style)],
    ], colWidths=[42 * mm, 128 * mm])

    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    elements.append(meta_table)
    elements.append(Spacer(1, 10))

    metric_row = Table([[
        metric_card("HIGH", str(high), "#B91C1C", "#FEF2F2"),
        metric_card("MEDIUM", str(medium), "#B45309", "#FFFBEB"),
        metric_card("LOW", str(low), "#15803D", "#F0FDF4"),
        metric_card("TOTAL", str(total_findings), "#1D4ED8", "#EFF6FF"),
    ]], colWidths=[42 * mm, 42 * mm, 42 * mm, 42 * mm])

    metric_row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    elements.append(metric_row)
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Executive Summary", section_title_style))
    summary_box = Table([
        [Paragraph(clean_text(summary_text, strip_tags=False), body_style)]
    ], colWidths=[170 * mm])

    summary_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#E2E8F0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(summary_box)
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("Assessment Notes", section_title_style))
    notes_box = Table([
        [Paragraph(
            "This report is based on the stored scan result produced by the Web Guardian platform. "
            "Findings should be reviewed and validated by the responsible technical team "
            "before remediation decisions are finalized.",
            body_style
        )]
    ], colWidths=[170 * mm])

    notes_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#E2E8F0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    elements.append(notes_box)

    # ---- Findings overview ----
    elements.append(PageBreak())
    elements.append(Paragraph("Findings Overview", section_title_style))
    elements.append(Spacer(1, 4))

    if not vulns:
        no_findings_box = Table([
            [Paragraph("No vulnerabilities were recorded for this scan.", body_style)]
        ], colWidths=[170 * mm])

        no_findings_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
            ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#BBF7D0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(no_findings_box)
    else:
        overview_rows = [[
            Paragraph("No", table_header_style),
            Paragraph("Finding", table_header_style),
            Paragraph("Risk", table_header_style),
            Paragraph("CWE", table_header_style),
            Paragraph("Technical Summary", table_header_style),
        ]]

        for idx, v in enumerate(vulns, start=1):
            risk_val = extract_risk(v)
            risk_colors = get_risk_colors(risk_val)

            overview_rows.append([
                Paragraph(str(idx), table_cell_style),
                Paragraph(clean_text(clip(pick_name(v), 65)), table_cell_style),
                Paragraph(
                    f'<font color="{risk_colors["accent"]}"><b>{risk_val}</b></font>',
                    ParagraphStyle(
                        "risk_overview_style",
                        parent=table_cell_style,
                        alignment=1
                    )
                ),
                Paragraph(clean_text(pick_cwe(v)), ParagraphStyle(
                    "cwe_overview_style",
                    parent=table_cell_style,
                    alignment=1
                )),
                Paragraph(clean_text(clip(pick_desc(v), 120)), table_cell_style),
            ])

        overview_table = Table(
            overview_rows,
            colWidths=[12 * mm, 48 * mm, 22 * mm, 18 * mm, 70 * mm],
            repeatRows=1
        )

        overview_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("ALIGN", (2, 1), (3, -1), "CENTER"),
        ]))

        elements.append(overview_table)

    # ---- Detailed findings ----
    if vulns:
        for idx, v in enumerate(vulns, start=1):
            elements.append(PageBreak())

            risk_val = extract_risk(v)
            risk_ui = get_risk_colors(risk_val)

            raw_name = pick_name(v)
            raw_desc = pick_desc(v)
            raw_solution = pick_solution(v)
            raw_reference = pick_reference(v)

            plain_info = get_plain_language_details(raw_name, risk_val, raw_desc)

            evidence_lines = "<br/>".join(
                [clean_text(line, strip_tags=False) for line in extract_evidence(v)]
            )

            header_table = Table([
                [
                    Paragraph(f"Finding {idx}", small_muted_style),
                    build_pill(risk_val.upper(), risk_ui["pill_bg"], risk_ui["pill_fg"])
                ],
                [
                    Paragraph(clean_text(raw_name), finding_title_style),
                    ""
                ],
                [
                    Paragraph(f"<b>Target:</b> {target_url}", small_style),
                    ""
                ],
                [
                    Paragraph(f"<b>Scan Date:</b> {display_date} &nbsp;&nbsp;&nbsp; <b>Scan Time:</b> {display_time}", small_style),
                    ""
                ],
            ], colWidths=[145 * mm, 25 * mm])

            header_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#E2E8F0")),
                ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(risk_ui["accent"])),
                ("SPAN", (0, 1), (1, 1)),
                ("SPAN", (0, 2), (1, 2)),
                ("SPAN", (0, 3), (1, 3)),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ]))
            elements.append(header_table)
            elements.append(Spacer(1, 8))

            summary_detail_table = Table([
                [Paragraph("<b>What this means</b>", sub_box_title_style),
                 Paragraph(clean_text(clip(plain_info["what_this_means"], 250, strip_tags=False)), body_style)],
                [Paragraph("<b>Impact</b>", sub_box_title_style),
                 Paragraph(clean_text(clip(plain_info["business_impact"], 250, strip_tags=False)), body_style)],
                [Paragraph("<b>Recommended action</b>", sub_box_title_style),
                 Paragraph(clean_text(clip(plain_info["recommended_action"], 250, strip_tags=False)), body_style)],
            ], colWidths=[42 * mm, 128 * mm])

            summary_detail_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(risk_ui["bg"])),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#E2E8F0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            elements.append(summary_detail_table)
            elements.append(Spacer(1, 8))

            technical_table = Table([
                [Paragraph("<b>Evidence</b>", sub_box_title_style), Paragraph(evidence_lines, small_style)],
                [Paragraph("<b>Technical Details</b>", sub_box_title_style), Paragraph(clean_text(clip(raw_desc, 700)), small_style)],
                [Paragraph("<b>Fix / Solution</b>", sub_box_title_style), Paragraph(clean_text(clip(raw_solution, 500)), small_style)],
                [Paragraph("<b>CWE</b>", sub_box_title_style), Paragraph(clean_text(pick_cwe(v)), small_style)],
                [Paragraph("<b>WASC</b>", sub_box_title_style), Paragraph(clean_text(pick_wasc(v)), small_style)],
                [Paragraph("<b>Reference</b>", sub_box_title_style), Paragraph(clean_text(raw_reference), small_style)],
            ], colWidths=[42 * mm, 128 * mm])

            technical_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#E2E8F0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(technical_table)

    elements.append(Spacer(1, 6))
    elements.append(Paragraph("Generated by Web Guardian - Internal Use Only", small_muted_style))

    # =========================
    # Header / Footer
    # =========================
    def draw_header_footer(canv, doc_obj):
        canv.saveState()

        # top band
        canv.setFillColor(colors.HexColor("#0F172A"))
        canv.rect(0, A4[1] - 13 * mm, A4[0], 13 * mm, stroke=0, fill=1)

        canv.setFillColor(colors.white)
        canv.setFont("Helvetica-Bold", 10)
        canv.drawString(14 * mm, A4[1] - 8.5 * mm, "WEB GUARDIAN")

        canv.setFont("Helvetica", 8.5)
        canv.drawRightString(A4[0] - 14 * mm, A4[1] - 8.5 * mm, "Security Scan Report")

        # bottom line
        canv.setStrokeColor(colors.HexColor("#CBD5E1"))
        canv.setLineWidth(0.8)
        canv.line(14 * mm, 10 * mm, A4[0] - 14 * mm, 10 * mm)

        canv.setFillColor(colors.HexColor("#64748B"))
        canv.setFont("Helvetica", 8)
        canv.drawString(14 * mm, 6.5 * mm, f"Target: {re.sub(r'<[^>]*>', '', str(scan.get('target_url') or '-'))[:65]}")
        canv.drawRightString(A4[0] - 14 * mm, 6.5 * mm, f"Page {canv.getPageNumber()}")

        canv.restoreState()

    doc.build(
        elements,
        onFirstPage=draw_header_footer,
        onLaterPages=draw_header_footer
    )

    buffer.seek(0)

    download_name = f"WebGuardian_Scan_Report_{scan_id}.pdf"
    content_disposition = (
        f'attachment; filename="{download_name}"; '
        f"filename*=UTF-8''{download_name}"
    )

    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={
            "Content-Disposition": content_disposition,
            "X-Content-Type-Options": "nosniff",
        }
    )

@app.route('/admin/set-status/<int:user_id>/<status>', methods=['POST'])
@login_required(role='admin')
def set_user_status(user_id, status):
    if status not in ['active', 'inactive']:
        flash("Invalid status.", "danger")
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT name FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()

        if not user:
            conn.close()
            flash("User not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        cursor.execute("UPDATE users SET status=%s WHERE id=%s", (status, user_id))
        conn.commit()

    conn.close()

    flash(f"Status for {user['name']} changed to {status}.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/view-pdf/<path:filename>')
@login_required()
def view_pdf(filename):
    safe_name = secure_filename(filename)

    if not safe_name:
        flash("Invalid file name.", "danger")
        return redirect(request.referrer or url_for('dashboard'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
    if not os.path.exists(file_path):
        flash("PDF file not found.", "danger")
        return redirect(request.referrer or url_for('dashboard'))

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        safe_name,
        as_attachment=False
    )

# ===== LOGOUT =====
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()

    resp = redirect(url_for('login'))

    resp.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"))

    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"

    flash("You have been logged out.", "info")
    return resp

if __name__ == '__main__':
    print("=" * 60)
    print("WEB GUARDIAN - ZAP ACTIVE SCANNER")
    print("=" * 60)

    # Test database
    try:
        conn = get_db_connection()
        conn.close()
        print("Database connection successful")
    except Exception as e:
        print(f"Database error: {e}")

    print("-" * 60)
    print("Starting Flask application...")
    print("Access at: http://localhost:5000")
    print("=" * 60)

    app.run(
        debug=os.environ.get("FLASK_DEBUG", "False").lower() == "true",
        host='0.0.0.0',
        port=5000
    )