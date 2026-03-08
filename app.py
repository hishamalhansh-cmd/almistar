import os
import re
import sqlite3
import random
import smtplib
import uuid
import json
import time
import imghdr
from flask import Flask, render_template_string, request, redirect, session, url_for, send_from_directory
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "adam_secret_key_2026"

# ================= الإعدادات =================
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "")
SENDER_APP_PASSWORD = os.environ.get("SENDER_APP_PASSWORD", "")

CONTACT_PHONE = "009647864145165"
CONTACT_EMAIL = "hishamalhanash@gmail.com"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB لكل طلب

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_SINGLE_FILE_SIZE = 3 * 1024 * 1024
MAX_WORK_IMAGES = 10

IRAQ_GOVERNORATES = [
    "بغداد", "البصرة", "نينوى", "أربيل", "النجف", "كربلاء", "الأنبار",
    "بابل", "ذي قار", "ديالى", "دهوك", "السليمانية", "صلاح الدين",
    "كركوك", "واسط", "ميسان", "المثنى", "القادسية", "حلبجة", "الناصرية"
]

SPECIALTY_GROUPS = {
    "مهندسون": [
        "مهندس كهربائيات",
        "مهندس معماري",
        "مهندس انشاء",
        "مهندس ديكور وتصميم"
    ],
    "خلفه بناء": [
        "خلفه اشتايكر",
        "خلفه طابوك",
        "خلفه سيراميك والرضيه",
        "خلفه جص (ابياض)",
        "خلفه قالب نجار"
    ],
    "عمال بناء": [
        "عمال بناء"
    ],
    "مواد بناء": [
        "مواد بناء"
    ],
    "فنيين": [
        "فني كهرباء",
        "فني تبريد",
        "فني ماء",
        "فني صحيات"
    ]
}

SPECIALTIES = [item for group in SPECIALTY_GROUPS.values() for item in group]

LOGIN_ATTEMPTS = {}
MESSAGE_RATE_LIMIT = {}
COMMENT_RATE_LIMIT = {}

LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 5

MESSAGE_WINDOW_SECONDS = 20
MESSAGE_MAX_COUNT = 5

COMMENT_WINDOW_SECONDS = 120
COMMENT_MAX_COUNT = 3


# ================= أدوات الحماية والتحقق =================
def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def clean_old_attempts(storage, window_seconds):
    now = time.time()
    expired_keys = []
    for key, timestamps in list(storage.items()):
        filtered = [t for t in timestamps if now - t <= window_seconds]
        if filtered:
            storage[key] = filtered
        else:
            expired_keys.append(key)
    for key in expired_keys:
        storage.pop(key, None)


def too_many_attempts(storage, key, window_seconds, max_count):
    clean_old_attempts(storage, window_seconds)
    now = time.time()
    arr = storage.get(key, [])
    arr = [t for t in arr if now - t <= window_seconds]
    if len(arr) >= max_count:
        storage[key] = arr
        return True
    arr.append(now)
    storage[key] = arr
    return False


def normalize_spaces(text):
    text = (text or "").strip()
    return re.sub(r"\s+", " ", text)


def sanitize_input(text, max_length=300):
    text = normalize_spaces(text)
    text = text.replace("<", "").replace(">", "")
    if len(text) > max_length:
        text = text[:max_length]
    return text


def valid_email(email):
    email = (email or "").strip()
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email) is not None and len(email) <= 120


def normalize_iraq_phone(phone):
    digits = "".join(ch for ch in (phone or "") if ch.isdigit())

    if digits.startswith("964"):
        return "+" + digits

    if digits.startswith("0"):
        digits = digits[1:]

    if not digits.startswith("964"):
        digits = "964" + digits

    return "+" + digits


def valid_phone(phone):
    normalized = normalize_iraq_phone(phone)
    digits = "".join(ch for ch in normalized if ch.isdigit())
    return digits.startswith("964") and 12 <= len(digits) <= 15


def valid_password(password):
    return password is not None and len(password.strip()) >= 4


def file_size_ok(file_obj):
    try:
        current_pos = file_obj.stream.tell()
        file_obj.stream.seek(0, os.SEEK_END)
        size = file_obj.stream.tell()
        file_obj.stream.seek(current_pos)
        return size <= MAX_SINGLE_FILE_SIZE
    except Exception:
        return False


def detect_real_image_type(file_obj):
    try:
        current_pos = file_obj.stream.tell()
        file_obj.stream.seek(0)
        header = file_obj.stream.read(512)
        file_obj.stream.seek(current_pos)
        detected = imghdr.what(None, header)
        if detected == "jpeg":
            return "jpg"
        return detected
    except Exception:
        return None


def validate_uploaded_image(file_obj):
    if not file_obj or file_obj.filename == "":
        return False, "لا يوجد ملف"

    if not allowed_file(file_obj.filename):
        return False, "نوع الملف غير مسموح"

    if not file_size_ok(file_obj):
        return False, "حجم الصورة أكبر من المسموح"

    real_type = detect_real_image_type(file_obj)
    if real_type not in ALLOWED_EXTENSIONS:
        return False, "الملف المرفوع ليس صورة صحيحة"

    return True, ""


# ================= أدوات الاختصاصات والمحافظات =================
def get_main_group_by_specialty(specialty):
    for group_name, items in SPECIALTY_GROUPS.items():
        if specialty in items:
            return group_name
    return ""


def build_main_groups_options(selected_value=""):
    html = ""
    for group_name in SPECIALTY_GROUPS.keys():
        selected = "selected" if group_name == selected_value else ""
        html += f'<option value="{group_name}" {selected}>{group_name}</option>'
    return html


def build_specialties_options(selected_value="", group_name=""):
    html = ""
    items = SPECIALTY_GROUPS.get(group_name, []) if group_name else SPECIALTIES
    for item in items:
        selected = "selected" if item == selected_value else ""
        html += f'<option value="{item}" {selected}>{item}</option>'
    return html


def build_governorates_options(selected_value=""):
    html = ""
    for gov in IRAQ_GOVERNORATES:
        selected = "selected" if gov == selected_value else ""
        html += f'<option value="{gov}" {selected}>{gov}</option>'
    return html


def specialty_script(selected_value=""):
    groups_json = json.dumps(SPECIALTY_GROUPS, ensure_ascii=False)
    return f"""
    <script>
    const specialtyGroups = {groups_json};

    function updateSpecialties(selectedValue = "") {{
        const mainGroup = document.getElementById("main_group");
        const sectionSelect = document.getElementById("section");
        if (!mainGroup || !sectionSelect) return;

        const chosen = mainGroup.value;
        sectionSelect.innerHTML = '<option value="">اختر الاختصاص</option>';

        if (specialtyGroups[chosen]) {{
            specialtyGroups[chosen].forEach(function(item) {{
                const option = document.createElement("option");
                option.value = item;
                option.textContent = item;
                if (item === selectedValue) {{
                    option.selected = true;
                }}
                sectionSelect.appendChild(option);
            }});
        }}
    }}

    document.addEventListener("DOMContentLoaded", function() {{
        updateSpecialties({json.dumps(selected_value, ensure_ascii=False)});
    }});
    </script>
    """


def build_whatsapp_link(phone):
    digits = "".join(ch for ch in (phone or "") if ch.isdigit())
    if not digits:
        return "#"
    if digits.startswith("00"):
        digits = digits[2:]
    return f"https://wa.me/{digits}"


# ================= أدوات الصور =================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_uploaded_file(file_obj):
    if not file_obj or file_obj.filename == "":
        return ""

    is_valid, _ = validate_uploaded_image(file_obj)
    if not is_valid:
        return ""

    original = secure_filename(file_obj.filename)
    ext = original.rsplit(".", 1)[1].lower()
    if ext == "jpeg":
        ext = "jpg"

    unique_name = f"{uuid.uuid4().hex}.{ext}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

    try:
        file_obj.stream.seek(0)
    except Exception:
        pass

    file_obj.save(save_path)
    return unique_name


def delete_file_if_exists(filename):
    if not filename:
        return
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ================= قاعدة البيانات =================
def get_db():
    con = sqlite3.connect("database.db")
    con.row_factory = sqlite3.Row
    return con


def table_columns(cur, table_name):
    cur.execute(f"PRAGMA table_info({table_name})")
    return [col[1] for col in cur.fetchall()]


def column_exists(cur, table_name, column_name):
    return column_name in table_columns(cur, table_name)


def init_db():
    with get_db() as con:
        cur = con.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            phone TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT,
            section TEXT,
            city TEXT,
            exp TEXT,
            bio TEXT
        )
        """)

        if not column_exists(cur, "users", "is_verified"):
            cur.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0")

        if not column_exists(cur, "users", "profile_pic"):
            cur.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT DEFAULT ''")

        if not column_exists(cur, "users", "work_images"):
            cur.execute("ALTER TABLE users ADD COLUMN work_images TEXT DEFAULT ''")

        if not column_exists(cur, "users", "governorate"):
            cur.execute("ALTER TABLE users ADD COLUMN governorate TEXT DEFAULT ''")

        if not column_exists(cur, "users", "show_phone"):
            cur.execute("ALTER TABLE users ADD COLUMN show_phone INTEGER DEFAULT 1")

        if not column_exists(cur, "users", "show_whatsapp"):
            cur.execute("ALTER TABLE users ADD COLUMN show_whatsapp INTEGER DEFAULT 1")

        if not column_exists(cur, "users", "allow_messages"):
            cur.execute("ALTER TABLE users ADD COLUMN allow_messages INTEGER DEFAULT 1")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_name TEXT,
            receiver_name TEXT,
            msg TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        if not column_exists(cur, "messages", "is_read"):
            cur.execute("ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS admin_settings(
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS admin_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_username TEXT,
            action TEXT,
            target_name TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS comments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            commenter_name TEXT,
            rating INTEGER,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_section ON users(section)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_city ON users(city)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_governorate ON users(governorate)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_verified ON users(is_verified)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver ON messages(sender_name, receiver_name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_read ON messages(is_read)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_comments_user_commenter ON comments(user_id, commenter_name)")

        admin_row = cur.execute("SELECT * FROM admin_settings WHERE id=1").fetchone()
        if not admin_row:
            cur.execute(
                "INSERT INTO admin_settings (id, username, password) VALUES (1, ?, ?)",
                ("admin", generate_password_hash("1234"))
            )
        else:
            admin_pwd = admin_row["password"] or ""
            if admin_pwd and not admin_pwd.startswith("pbkdf2:") and not admin_pwd.startswith("scrypt:"):
                cur.execute(
                    "UPDATE admin_settings SET password=? WHERE id=1",
                    (generate_password_hash(admin_pwd),)
                )

        users = cur.execute("SELECT id, password FROM users").fetchall()
        for u in users:
            pwd = u["password"] or ""
            if pwd and not pwd.startswith("pbkdf2:") and not pwd.startswith("scrypt:"):
                cur.execute(
                    "UPDATE users SET password=? WHERE id=?",
                    (generate_password_hash(pwd), u["id"])
                )

        con.commit()

    print("تم تجهيز قاعدة البيانات بنجاح")


init_db()


# ================= سجل الأدمن =================
def log_admin_action(action, target_name="", details=""):
    admin_username = session.get("admin_username", "admin")
    with get_db() as con:
        con.execute(
            "INSERT INTO admin_logs(admin_username, action, target_name, details) VALUES(?,?,?,?)",
            (admin_username, action, target_name, details)
        )
        con.commit()


# ================= إرسال الإيميل =================
def send_mail(to_email, subject, body):
    try:
        if not SENDER_EMAIL or not SENDER_APP_PASSWORD:
            print("MAIL ERROR: missing SENDER_EMAIL or SENDER_APP_PASSWORD")
            return False

        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print("MAIL ERROR:", e)
        return False


# ================= الستايل =================
STYLE = """
<style>
*{box-sizing:border-box}
body{
    background:linear-gradient(180deg,#FFD700 0%,#f3cd00 100%);
    font-family:Arial;
    direction:rtl;
    text-align:center;
    margin:0;
    color:#111;
    min-height:100vh;
}
.container{
    width:380px;
    max-width:92%;
    margin:20px auto;
    background:rgba(255,255,255,0.97);
    padding:22px;
    border-radius:22px;
    box-shadow:0 10px 30px rgba(0,0,0,0.12);
    border:1px solid rgba(255,255,255,0.6);
    backdrop-filter:blur(4px);
}
input, select, textarea{
    width:100%;
    padding:12px 14px;
    margin:7px 0;
    border:1px solid #ddd;
    border-radius:14px;
    box-sizing:border-box;
    background:#fff;
    font-size:15px;
    outline:none;
    transition:.2s;
}
input:focus, select:focus, textarea:focus{
    border-color:#111;
    box-shadow:0 0 0 3px rgba(255,215,0,0.25);
}
button{
    width:100%;
    padding:13px;
    background:linear-gradient(135deg,#111 0%,#222 100%);
    color:#FFD700;
    border:none;
    border-radius:14px;
    cursor:pointer;
    font-weight:bold;
    margin-top:8px;
    font-size:15px;
    transition:.2s;
    box-shadow:0 6px 16px rgba(0,0,0,0.16);
}
button:hover{
    opacity:.96;
    transform:translateY(-1px);
}
a{text-decoration:none;color:black;}
.card{
    background:rgba(255,255,255,0.98);
    padding:16px;
    margin:12px auto;
    width:360px;
    max-width:92%;
    border-radius:18px;
    border:1px solid #ececec;
    box-shadow:0 6px 18px rgba(0,0,0,0.08);
}
.profile-img{
    width:100px;
    height:100px;
    border-radius:50%;
    object-fit:cover;
    border:4px solid #FFD700;
    display:block;
    margin:0 auto 10px auto;
    background:#f0f0f0;
}
.profile-img-large{
    width:140px;
    height:140px;
    border-radius:50%;
    object-fit:cover;
    border:4px solid #FFD700;
    display:block;
    margin:0 auto 12px auto;
    background:#f0f0f0;
}
.profile-placeholder{
    width:100px;
    height:100px;
    border-radius:50%;
    border:4px solid #FFD700;
    background:#f3f3f3;
    display:flex;
    align-items:center;
    justify-content:center;
    margin:0 auto 10px auto;
    font-size:40px;
    color:#777;
}
.profile-placeholder-large{
    width:140px;
    height:140px;
    border-radius:50%;
    border:4px solid #FFD700;
    background:#f3f3f3;
    display:flex;
    align-items:center;
    justify-content:center;
    margin:0 auto 12px auto;
    font-size:54px;
    color:#777;
}
.work-gallery{
    display:flex;
    justify-content:center;
    gap:8px;
    flex-wrap:wrap;
    margin:10px 0;
}
.work-img{
    width:75px;
    height:75px;
    border-radius:10px;
    object-fit:cover;
    background:#f0f0f0;
    border:1px solid #ddd;
}
.work-img-large{
    width:120px;
    height:120px;
    border-radius:12px;
    object-fit:cover;
    background:#f0f0f0;
    border:1px solid #ddd;
}
.msg{
    background:#fff7c8;
    border:1px solid #f0dd76;
    padding:12px;
    border-radius:14px;
    margin:12px 0;
    line-height:1.7;
}
.actions-row{
    display:flex;
    gap:8px;
    margin-top:10px;
    flex-wrap:wrap;
}
.actions-row a, .actions-row form, .actions-row div{flex:1;}
.chat-box{
    background:#fffdf0;
    border:1px solid #eadf9c;
    border-radius:16px;
    padding:12px;
    margin:10px auto;
    width:380px;
    max-width:92%;
    box-sizing:border-box;
}
.chat-msg{
    background:white;
    border:1px solid #eee;
    border-radius:12px;
    padding:10px;
    margin:8px 0;
    text-align:right;
}
.chat-time{font-size:11px;color:#666;margin-top:4px;}
.chat-status{font-size:11px;color:#444;margin-top:4px;}
table{
    width:100%;
    border-collapse:collapse;
    background:white;
    font-size:12px;
    margin-top:20px;
    border-radius:14px;
    overflow:hidden;
}
th, td{border:1px solid #eee;padding:8px;text-align:center;}
th{background:#222;color:#FFD700;}
.name-link{color:#111;font-weight:bold;font-size:20px;}
.info-line{margin:7px 0;font-size:17px;line-height:1.8;}
.image-card{width:120px;text-align:center;}
.small-btn{padding:8px;font-size:12px;margin-top:6px;}
.rating-stars{font-size:20px;margin:8px 0;}
.search-row{display:flex;gap:8px;flex-wrap:wrap;}
.search-row > *{flex:1;min-width:150px;}
.comment-box{
    background:#fffdf6;
    border:1px solid #eee;
    border-radius:14px;
    padding:12px;
    margin:10px 0;
    text-align:right;
}
.unread-badge{
    display:inline-block;
    background:#d60000;
    color:white;
    border-radius:20px;
    padding:4px 9px;
    font-size:11px;
    margin-top:8px;
}
.settings-btn{
    position:fixed;
    top:12px;
    left:12px;
    width:48px;
    height:48px;
    border-radius:50%;
    background:#111;
    color:#FFD700;
    border:none;
    font-size:24px;
    font-weight:bold;
    cursor:pointer;
    z-index:9999;
    box-shadow:0 6px 16px rgba(0,0,0,0.18);
}
.settings-btn:hover{opacity:.92;}
.settings-menu-card{
    background:rgba(255,255,255,0.98);
    padding:15px;
    margin:10px auto;
    width:360px;
    max-width:92%;
    border-radius:18px;
    border:1px solid #ececec;
    text-align:right;
    box-shadow:0 6px 18px rgba(0,0,0,0.08);
}
.settings-title{
    font-size:20px;
    font-weight:bold;
    margin-bottom:10px;
}
.settings-item{
    display:block;
    background:#fffdf5;
    border:1px solid #eee;
    border-radius:14px;
    padding:12px;
    margin:8px 0;
    text-align:right;
    font-weight:bold;
}
.settings-item small{
    display:block;
    color:#555;
    font-weight:normal;
    margin-top:4px;
    line-height:1.6;
}
.top-left-settings{position:fixed;top:12px;left:12px;z-index:9999;}
.top-left-settings a button{
    width:48px;
    height:48px;
    border-radius:50%;
    padding:0;
    font-size:24px;
    margin:0;
}
.contact-card{
    background:white;
    padding:15px;
    margin:10px auto;
    width:360px;
    max-width:92%;
    border-radius:18px;
    border:1px solid #ddd;
    box-shadow:0 6px 18px rgba(0,0,0,0.08);
}
.search-toggle-btn{
    width:100%;
    padding:12px;
    background:#111;
    color:#FFD700;
    border:none;
    border-radius:14px;
    cursor:pointer;
    font-weight:bold;
    margin-top:10px;
}
.search-panel{
    display:none;
    margin-top:12px;
    padding:12px;
    background:#fffdf5;
    border:1px solid #eee;
    border-radius:16px;
}
.section-grid{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:10px;
    margin-top:15px;
}
.section-grid a button{
    margin-top:0;
    border-radius:14px;
}
.main-card{
    width:420px;
    max-width:92%;
}
.top-actions{
    display:flex;
    gap:10px;
    margin-top:12px;
}
.top-actions a{flex:1;}
.result-card{
    background:white;
    padding:16px;
    margin:12px auto;
    width:420px;
    max-width:92%;
    border-radius:18px;
    border:1px solid #e9e9e9;
    box-shadow:0 8px 20px rgba(0,0,0,0.08);
}
.result-card h3{margin:8px 0;}
.soft-btn{
    background:#111;
    color:#FFD700;
    border:none;
    border-radius:12px;
    padding:11px;
    cursor:pointer;
    font-weight:bold;
}
.soft-btn.red{
    background:#d90000;
    color:white;
}
.admin-fab{
    position:fixed;
    bottom:16px;
    left:16px;
    width:56px;
    height:56px;
    border-radius:50%;
    background:linear-gradient(135deg,#111 0%,#2a2a2a 100%);
    color:#FFD700;
    border:none;
    font-size:24px;
    cursor:pointer;
    z-index:9999;
    box-shadow:0 8px 20px rgba(0,0,0,0.22);
    display:flex;
    align-items:center;
    justify-content:center;
}
.admin-fab:hover{
    opacity:.95;
    transform:translateY(-2px);
}
.login-helper{
    margin-top:12px;
    font-size:14px;
    color:#555;
    line-height:1.8;
}
.login-helper a{
    color:#111;
    font-weight:bold;
    text-decoration:none;
}
.login-helper a:hover{
    text-decoration:underline;
}
.hero-box{
    width:420px;
    max-width:92%;
    margin:30px auto 20px auto;
    background:rgba(255,255,255,0.97);
    border-radius:28px;
    padding:28px 22px;
    box-shadow:0 15px 35px rgba(0,0,0,0.12);
    position:relative;
    overflow:hidden;
}
.hero-badge{
    display:inline-block;
    background:#111;
    color:#FFD700;
    padding:8px 14px;
    border-radius:999px;
    font-size:13px;
    font-weight:bold;
    margin-bottom:14px;
}
.hero-title{
    font-size:34px;
    font-weight:bold;
    margin:0 0 10px 0;
    color:#111;
}
.hero-sub{
    font-size:15px;
    color:#555;
    line-height:1.9;
    margin-bottom:18px;
}
.main-btn{
    display:block;
    width:100%;
}
.secondary-btn{
    display:block;
    width:100%;
}
.secondary-btn button{
    background:white;
    color:#111;
    border:1px solid #ddd;
}
.divider-line{
    display:flex;
    align-items:center;
    gap:10px;
    margin:16px 0;
    color:#777;
    font-size:13px;
}
.divider-line::before,
.divider-line::after{
    content:"";
    flex:1;
    height:1px;
    background:#e2e2e2;
}
.form-title{
    font-size:26px;
    font-weight:bold;
    margin-bottom:8px;
}
.form-subtitle{
    color:#666;
    font-size:14px;
    margin-bottom:16px;
    line-height:1.8;
}
@media (max-width:480px){
    .hero-title{font-size:29px;}
    .container{padding:18px;}
}
</style>
"""


def settings_corner():
    if "user" in session:
        return '<div class="top-left-settings"><a href="/settings"><button title="الإعدادات">⚙️</button></a></div>'
    return ""


# ================= الصفحة الرئيسية =================
@app.route("/")
def home():
    return render_template_string(STYLE + """
    <div class="hero-box">
        <div class="hero-badge">منصة المهنيين</div>
        <div class="hero-title">المسطر</div>
        <div class="hero-sub">
            منصة تساعدك توصل للمهني المناسب بسهولة حسب الاختصاص والمحافظة والمدينة،
            مع بروفايل مهني، صور أعمال، تقييمات، ورسائل داخل التطبيق.
        </div>

        <a href="/login" class="main-btn"><button>تسجيل دخول</button></a>

        <div class="login-helper">
            لا أملك حساب؟ <a href="/register">قم بإنشاء حساب</a>
        </div>

        <div class="divider-line">أو</div>

        <a href="/register" class="secondary-btn"><button>إنشاء حساب جديد</button></a>
    </div>

    <a href="/admin" class="admin-fab" title="دخول الأدمن">⚙️</a>
    """)


# ================= إنشاء حساب =================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        d = {
            "name": sanitize_input(request.form.get("name", ""), 80),
            "phone": sanitize_input(request.form.get("phone", ""), 25),
            "email": sanitize_input(request.form.get("email", ""), 120).lower(),
            "password": request.form.get("password", "").strip(),
            "role": sanitize_input(request.form.get("role", ""), 20),
            "section": sanitize_input(request.form.get("section", ""), 80),
            "governorate": sanitize_input(request.form.get("governorate", ""), 80),
            "city": sanitize_input(request.form.get("city", ""), 80),
            "exp": sanitize_input(request.form.get("exp", ""), 30),
            "bio": sanitize_input(request.form.get("bio", ""), 500)
        }

        if not d["name"] or not d["phone"] or not d["email"] or not d["password"] or not d["section"] or not d["governorate"] or not d["city"] or not d["exp"]:
            return render_template_string(STYLE + """
            <div class="container"><div class="msg">اكمل الحقول الأساسية</div><a href="/register"><button>رجوع</button></a></div>
            """)

        if not valid_email(d["email"]):
            return render_template_string(STYLE + """
            <div class="container"><div class="msg">البريد الإلكتروني غير صحيح</div><a href="/register"><button>رجوع</button></a></div>
            """)

        if d["governorate"] not in IRAQ_GOVERNORATES:
            return render_template_string(STYLE + """
            <div class="container"><div class="msg">المحافظة غير صحيحة</div><a href="/register"><button>رجوع</button></a></div>
            """)

        d["phone"] = normalize_iraq_phone(d["phone"])

        if not valid_phone(d["phone"]):
            return render_template_string(STYLE + """
            <div class="container"><div class="msg">رقم الهاتف غير صحيح. اكتب الرقم بصيغة عراقية</div><a href="/register"><button>رجوع</button></a></div>
            """)

        if not valid_password(d["password"]):
            return render_template_string(STYLE + """
            <div class="container"><div class="msg">كلمة المرور يجب أن تكون 4 أحرف أو أرقام على الأقل</div><a href="/register"><button>رجوع</button></a></div>
            """)

        if d["section"] not in SPECIALTIES:
            return render_template_string(STYLE + """
            <div class="container"><div class="msg">الاختصاص غير صحيح</div><a href="/register"><button>رجوع</button></a></div>
            """)

        d["role"] = "pro"

        with get_db() as con:
            cur = con.cursor()
            old = cur.execute("SELECT id FROM users WHERE phone=? OR email=?", (d["phone"], d["email"])).fetchone()
            if old:
                return render_template_string(STYLE + """
                <div class="container"><div class="msg">رقم الهاتف أو البريد الإلكتروني مستخدم مسبقاً</div><a href="/register"><button>رجوع</button></a></div>
                """)

        profile_file = request.files.get("profile_pic")
        profile_name = ""

        if profile_file and profile_file.filename:
            valid_img, msg = validate_uploaded_image(profile_file)
            if not valid_img:
                return render_template_string(STYLE + f"""
                <div class="container"><div class="msg">{msg}</div><a href="/register"><button>رجوع</button></a></div>
                """)
            profile_name = save_uploaded_file(profile_file)

        work_files = request.files.getlist("work_images")
        work_names = []
        valid_work_files = [wf for wf in work_files if wf and wf.filename]

        if len(valid_work_files) > MAX_WORK_IMAGES:
            return render_template_string(STYLE + f"""
            <div class="container"><div class="msg">الحد الأقصى لصور الأعمال هو {MAX_WORK_IMAGES} صور</div><a href="/register"><button>رجوع</button></a></div>
            """)

        for wf in valid_work_files:
            valid_img, msg = validate_uploaded_image(wf)
            if not valid_img:
                return render_template_string(STYLE + f"""
                <div class="container"><div class="msg">{msg}</div><a href="/register"><button>رجوع</button></a></div>
                """)
            saved = save_uploaded_file(wf)
            if saved:
                work_names.append(saved)

        d["password"] = generate_password_hash(d["password"])
        d["profile_pic"] = profile_name
        d["work_images"] = ",".join(work_names)

        otp = str(random.randint(100000, 999999))
        session["pending_user"] = d
        session["otp"] = otp

        sent = send_mail(d["email"], "كود تفعيل حسابك", f"كود التفعيل الخاص بك هو: {otp}")
        if not sent:
            return render_template_string(STYLE + """
            <div class="container"><div class="msg">فشل إرسال الإيميل. تأكد من كلمة مرور التطبيق والإعدادات.</div><a href="/register"><button>رجوع</button></a></div>
            """)

        return redirect(url_for("verify"))

    groups_html = build_main_groups_options()
    gov_options = build_governorates_options()
    search_specialty_script = specialty_script()
    return render_template_string(STYLE + f"""
    <div class="container">
        <a href="/"><button>رجوع</button></a>
        <div class="form-title">إنشاء حساب جديد</div>
        <div class="form-subtitle">
            أنشئ حسابك المهني داخل تطبيق المسطر، وبعد تفعيل الإيميل راح يبقى الحساب بانتظار موافقة الأدمن حتى يظهر بالمنصة
        </div>
        <div class="msg">الحساب يحتاج موافقة الأدمن بعد التفعيل حتى يظهر في المنصة</div>
        <form method="post" enctype="multipart/form-data">
            <input name="name" placeholder="الاسم الكامل" required>
            <input name="phone" value="+964" placeholder="+964XXXXXXXXXX" required>
            <input name="email" placeholder="البريد الإلكتروني" required>
            <input type="password" name="password" placeholder="كلمة المرور" required>
            <input type="hidden" name="role" value="pro">

            <label>القسم الرئيسي</label>
            <select name="main_group" id="main_group" required onchange="updateSpecialties()">
                <option value="">اختر القسم الرئيسي</option>
                {groups_html}
            </select>

            <label>الاختصاص</label>
            <select name="section" id="section" required>
                <option value="">اختر الاختصاص</option>
            </select>

            <label>المحافظة</label>
            <select name="governorate" required>
                <option value="">اختر المحافظة</option>
                {gov_options}
            </select>

            <input name="city" placeholder="المدينة / المنطقة" required>
            <input name="exp" placeholder="سنوات الخبرة" required>
            <textarea name="bio" placeholder="نبذة عنك"></textarea>
            <label>الصورة الشخصية</label>
            <input type="file" name="profile_pic" accept=".png,.jpg,.jpeg,.gif,.webp">
            <label>صور أعمالك</label>
            <input type="file" name="work_images" multiple accept=".png,.jpg,.jpeg,.gif,.webp">
            <button>إنشاء الحساب</button>
        </form>
    </div>
    {search_specialty_script}
    """)


# ================= التحقق =================
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        if request.form.get("code") == session.get("otp"):
            d = session["pending_user"]
            with get_db() as con:
                con.execute("""
                INSERT INTO users
                (name, phone, email, password, role, section, governorate, city, exp, bio, profile_pic, work_images, is_verified)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)
                """, (
                    d["name"], d["phone"], d["email"], d["password"], d["role"], d["section"],
                    d["governorate"], d["city"], d["exp"], d["bio"], d["profile_pic"], d["work_images"]
                ))
                con.commit()
            session.clear()
            return render_template_string(STYLE + """
            <div class="container"><div class="msg">تم تفعيل الإيميل. الحساب الآن بانتظار موافقة الأدمن.</div><a href="/login"><button>تسجيل الدخول</button></a></div>
            """)
        return render_template_string(STYLE + """
        <div class="container"><div class="msg">كود خاطئ</div><a href="/verify"><button>رجوع</button></a></div>
        """)

    return render_template_string(STYLE + """
    <div class="container"><h2>أدخل كود التفعيل</h2><form method="post"><input name="code" placeholder="6 أرقام"><button>تأكيد</button></form></div>
    """)


# ================= تسجيل الدخول =================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = normalize_iraq_phone(sanitize_input(request.form.get("phone", ""), 25))
        password = request.form.get("password", "")

        ip = get_client_ip()
        if too_many_attempts(LOGIN_ATTEMPTS, ip, LOGIN_WINDOW_SECONDS, LOGIN_MAX_ATTEMPTS):
            return render_template_string(STYLE + """
            <div class="container"><div class="msg">محاولات دخول كثيرة. حاول بعد قليل</div><a href="/login"><button>رجوع</button></a></div>
            """)

        with get_db() as con:
            u = con.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()

        if u and check_password_hash(u["password"], password):
            LOGIN_ATTEMPTS.pop(ip, None)
            if u["is_verified"] != 1:
                return render_template_string(STYLE + """
                <div class="container"><div class="msg">الحساب بانتظار موافقة الأدمن</div><a href="/login"><button>رجوع</button></a></div>
                """)
            session["user"] = u["name"]
            return redirect(url_for("sections"))

        return render_template_string(STYLE + """
        <div class="container"><div class="msg">بيانات الدخول خاطئة</div><a href="/login"><button>رجوع</button></a></div>
        """)

    return render_template_string(STYLE + """
    <div class="container">
        <a href="/"><button>رجوع</button></a>
        <div class="form-title">تسجيل الدخول</div>
        <div class="form-subtitle">
            أهلاً بيك، سجل دخولك حتى تدخل لحسابك وتستخدم تطبيق المسطر
        </div>

        <form method="post">
            <input name="phone" value="+964" placeholder="+964XXXXXXXXXX">
            <input type="password" name="password" placeholder="كلمة المرور">
            <button>دخول</button>
        </form>

        <div class="login-helper">
            لا أملك حساب؟ <a href="/register">قم بإنشاء حساب</a>
        </div>

        <br>
        <a href="/forgot">نسيت كلمة السر؟</a>
    </div>
    """)


# ================= استعادة الحساب =================
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = sanitize_input(request.form.get("email", ""), 120).lower()
        if not valid_email(email):
            return render_template_string(STYLE + """
            <div class="container"><div class="msg">البريد الإلكتروني غير صحيح</div><a href="/forgot"><button>رجوع</button></a></div>
            """)
        otp = str(random.randint(100000, 999999))
        session["reset_email"] = email
        session["reset_otp"] = otp
        send_mail(email, "استعادة كلمة السر", f"كود استعادة كلمة السر هو: {otp}")
        return redirect(url_for("reset_password"))
    return render_template_string(STYLE + """
    <div class="container"><a href="/login"><button>رجوع</button></a><h2>استعادة الحساب</h2><form method="post"><input name="email" placeholder="بريدك الإلكتروني"><button>إرسال كود الاستعادة</button></form></div>
    """)


@app.route("/reset", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        new_pass = request.form.get("new_pass", "").strip()
        if otp == session.get("reset_otp"):
            if not valid_password(new_pass):
                return render_template_string(STYLE + """
                <div class="container"><div class="msg">كلمة السر الجديدة يجب أن تكون 4 أحرف أو أرقام على الأقل</div><a href="/reset"><button>رجوع</button></a></div>
                """)
            with get_db() as con:
                con.execute("UPDATE users SET password=? WHERE email=?", (generate_password_hash(new_pass), session["reset_email"]))
                con.commit()
            return render_template_string(STYLE + """
            <div class="container"><div class="msg">تم تغيير كلمة السر بنجاح</div><a href="/login"><button>دخول</button></a></div>
            """)
        return render_template_string(STYLE + """
        <div class="container"><div class="msg">كود خاطئ</div><a href="/reset"><button>رجوع</button></a></div>
        """)

    return render_template_string(STYLE + """
    <div class="container"><h2>تعيين كلمة سر جديدة</h2><form method="post"><input name="otp" placeholder="الكود المرسل"><input name="new_pass" placeholder="كلمة السر الجديدة"><button>تحديث</button></form></div>
    """)


# ================= الأقسام مع البحث =================
@app.route("/sections", methods=["GET"])
def sections():
    search_governorate = sanitize_input(request.args.get("governorate", ""), 80)
    search_city = sanitize_input(request.args.get("city", ""), 80)
    search_group = sanitize_input(request.args.get("group", ""), 80)
    search_section = sanitize_input(request.args.get("section", ""), 80)

    group_names = list(SPECIALTY_GROUPS.keys())
    results_html = ""
    has_search = bool(search_governorate or search_city or search_group or search_section)

    if has_search:
        params = []
        query = "SELECT * FROM users WHERE role='pro' AND is_verified=1"

        if search_governorate:
            query += " AND governorate=?"
            params.append(search_governorate)

        if search_city:
            query += " AND city LIKE ?"
            params.append(f"%{search_city}%")

        if search_section:
            query += " AND section=?"
            params.append(search_section)
        elif search_group and search_group in SPECIALTY_GROUPS:
            vals = SPECIALTY_GROUPS[search_group]
            query += f" AND section IN ({','.join(['?'] * len(vals))})"
            params.extend(vals)

        with get_db() as con:
            pros = con.execute(query, params).fetchall()

        if pros:
            for p in pros:
                img_block = f'<img src="{url_for("uploaded_file", filename=p["profile_pic"])}" class="profile-img" alt="profile">' if p["profile_pic"] else '<div class="profile-placeholder">👤</div>'
                whatsapp_link = build_whatsapp_link(p["phone"])
                phone_btn = f'<a href="tel:{p["phone"]}"><button class="soft-btn">اتصال مباشر</button></a>' if p["show_phone"] == 1 else ""
                whatsapp_btn = f'<a href="{whatsapp_link}" target="_blank"><button class="soft-btn">واتساب</button></a>' if p["show_whatsapp"] == 1 else ""

                results_html += f"""
                <div class='result-card'>
                    {img_block}
                    <h3><a class="name-link" href="/profile/{p['id']}">{p['name']}</a></h3>
                    <p><b>الاختصاص:</b> {p['section'] or '-'}</p>
                    <p><b>المحافظة:</b> {p['governorate'] or '-'}</p>
                    <p><b>المدينة:</b> {p['city'] or '-'}</p>
                    <p><b>الخبرة:</b> {p['exp'] or '-'}</p>
                    <div class="actions-row">
                        <a href="/profile/{p['id']}"><button class="soft-btn">عرض البروفايل</button></a>
                        {whatsapp_btn}
                    </div>
                    <div class="actions-row">
                        {phone_btn}
                    </div>
                </div>
                """
        else:
            results_html = """
            <div class="container">
                <div class="msg">ماكو نتائج مطابقة للبحث</div>
            </div>
            """

    groups_html = build_main_groups_options(search_group)
    gov_options = build_governorates_options(search_governorate)
    specialty_options = build_specialties_options(search_section, search_group)

    section_buttons = ""
    for s in group_names:
        section_buttons += f'<a href="/section/{s}"><button>{s}</button></a>'

    return render_template_string(STYLE + settings_corner() + f"""
    <div class="container main-card">
        <h2>الاختصاصات</h2>

        <button type="button" class="search-toggle-btn" onclick="toggleSearchPanel()">🔍 بحث</button>

        <div id="searchPanel" class="search-panel">
            <form method="get">
                <div class="search-row">
                    <select name="governorate">
                        <option value="">كل المحافظات</option>
                        {gov_options}
                    </select>

                    <input name="city" value="{search_city}" placeholder="ابحث حسب المدينة / المنطقة">

                    <select name="group" id="main_group" onchange="updateSpecialties()">
                        <option value="">كل الأقسام</option>
                        {groups_html}
                    </select>

                    <select name="section" id="section">
                        <option value="">كل الاختصاصات</option>
                        {specialty_options}
                    </select>
                </div>
                <button>بحث</button>
            </form>
        </div>

        <div class="section-grid">
            {section_buttons}
        </div>

        <div class="top-actions">
            <a href="/inbox"><button>الرسائل</button></a>
            <a href="/edit-profile"><button>تعديل البروفايل</button></a>
        </div>
    </div>

    {results_html}

    {specialty_script(search_section)}

    <script>
    function toggleSearchPanel() {{
        const panel = document.getElementById("searchPanel");
        if (panel.style.display === "block") {{
            panel.style.display = "none";
        }} else {{
            panel.style.display = "block";
        }}
    }}

    document.addEventListener("DOMContentLoaded", function() {{
        const hasSearch = {str(has_search).lower()};
        if (hasSearch) {{
            document.getElementById("searchPanel").style.display = "block";
        }}
    }});
    </script>
    """)


# ================= عرض القسم =================
@app.route("/section/<name>")
def section(name):
    name = sanitize_input(name, 80)
    with get_db() as con:
        if name in SPECIALTY_GROUPS:
            values = SPECIALTY_GROUPS[name]
            placeholders = ",".join(["?"] * len(values))
            pros = con.execute(f"SELECT * FROM users WHERE section IN ({placeholders}) AND role='pro' AND is_verified=1", values).fetchall()
        else:
            pros = con.execute("SELECT * FROM users WHERE section=? AND role='pro' AND is_verified=1", (name,)).fetchall()

    html = ""
    for p in pros:
        profile_block = f'<img src="{url_for("uploaded_file", filename=p["profile_pic"])}" class="profile-img" alt="profile">' if p["profile_pic"] else '<div class="profile-placeholder">👤</div>'
        gallery = ""
        if p["work_images"]:
            for img in p["work_images"].split(","):
                img = img.strip()
                if img:
                    img_url = url_for("uploaded_file", filename=img)
                    gallery += f'<img src="{img_url}" class="work-img" alt="work">'

        chat_btn = f'<a href="/chat/{p["name"]}"><button>محادثة</button></a>' if session.get("user") and session.get("user") != p["name"] and p["allow_messages"] == 1 else ""
        whatsapp_link = build_whatsapp_link(p["phone"])
        phone_btn = f'<a href="tel:{p["phone"]}"><button>اتصال مباشر</button></a>' if p["show_phone"] == 1 else ""
        whatsapp_btn = f'<a href="{whatsapp_link}" target="_blank"><button>واتساب مباشر</button></a>' if p["show_whatsapp"] == 1 else ""

        html += f"""
        <div class='card'>
            {profile_block}
            <h3><a class="name-link" href="/profile/{p['id']}">{p['name']}</a></h3>
            <p><b>الاختصاص:</b> {p['section'] or '-'}</p>
            <p><b>المحافظة:</b> {p['governorate'] or '-'}</p>
            <p><b>المدينة:</b> {p['city'] or '-'}</p>
            <p><b>الخبرة:</b> {p['exp'] or '-'}</p>
            <p>{p['bio'] or ''}</p>
            <div class="work-gallery">{gallery}</div>
            <div class="actions-row">
                <a href="/profile/{p['id']}"><button>عرض البروفايل</button></a>
                {phone_btn}
            </div>
            <div class="actions-row">
                {whatsapp_btn}
                {chat_btn}
            </div>
        </div>
        """

    return render_template_string(STYLE + settings_corner() + f'<div class="container"><h2>{name}</h2><a href="/sections"><button>رجوع للاختصاصات</button></a></div>' + (html or '<div class="container"><div class="msg">لا يوجد مهنيين في هذا القسم حالياً</div></div>'))


# ================= بروفايل المهني + تقييمات =================
@app.route("/profile/<int:user_id>", methods=["GET", "POST"])
def profile(user_id):
    with get_db() as con:
        pro = con.execute("SELECT * FROM users WHERE id=? AND role='pro'", (user_id,)).fetchone()

    if not pro or (pro["is_verified"] != 1 and session.get("user") != pro["name"] and "admin" not in session):
        return render_template_string(STYLE + settings_corner() + """
        <div class="container"><div class="msg">هذا البروفايل غير موجود</div><a href="/sections"><button>رجوع</button></a></div>
        """)

    if request.method == "POST":
        if "user" not in session:
            return redirect(url_for("login"))

        limit_key = f"{session.get('user')}::{user_id}"
        if too_many_attempts(COMMENT_RATE_LIMIT, limit_key, COMMENT_WINDOW_SECONDS, COMMENT_MAX_COUNT):
            return render_template_string(STYLE + settings_corner() + """
            <div class="container"><div class="msg">محاولات كثيرة لإضافة التعليقات. حاول بعد قليل</div><a href="/sections"><button>رجوع</button></a></div>
            """)

        rating = sanitize_input(request.form.get("rating", ""), 2)
        comment = sanitize_input(request.form.get("comment", ""), 500)

        try:
            rating_int = int(rating)
        except Exception:
            rating_int = 0

        if rating_int < 1 or rating_int > 5:
            return redirect(url_for("profile", user_id=user_id))

        with get_db() as con:
            old_comment = con.execute(
                "SELECT id FROM comments WHERE user_id=? AND commenter_name=?",
                (user_id, session.get("user"))
            ).fetchone()

            if old_comment:
                return render_template_string(STYLE + settings_corner() + f"""
                <div class="container">
                    <div class="msg">أنت أضفت تقييم سابق لهذا المهني، وما تگدر تكرر التقييم</div>
                    <a href="/profile/{user_id}"><button>رجوع للبروفايل</button></a>
                </div>
                """)

            con.execute(
                "INSERT INTO comments(user_id, commenter_name, rating, comment) VALUES(?,?,?,?)",
                (user_id, session.get("user"), rating_int, comment)
            )
            con.commit()

        return redirect(url_for("profile", user_id=user_id))

    with get_db() as con:
        comments = con.execute("SELECT * FROM comments WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()
        avg_row = con.execute("SELECT AVG(rating) AS avg_rating, COUNT(*) AS cnt FROM comments WHERE user_id=?", (user_id,)).fetchone()

    avg_rating = round(avg_row["avg_rating"], 1) if avg_row and avg_row["avg_rating"] is not None else 0
    rating_count = avg_row["cnt"] if avg_row else 0

    profile_block = f'<img src="{url_for("uploaded_file", filename=pro["profile_pic"])}" class="profile-img-large" alt="profile">' if pro["profile_pic"] else '<div class="profile-placeholder-large">👤</div>'

    gallery = ""
    if pro["work_images"]:
        for img in pro["work_images"].split(","):
            img = img.strip()
            if img:
                img_url = url_for("uploaded_file", filename=img)
                gallery += f'<img src="{img_url}" class="work-img-large" alt="work">'

    chat_btn = f'<a href="/chat/{pro["name"]}"><button>محادثة</button></a>' if session.get("user") and session.get("user") != pro["name"] and pro["allow_messages"] == 1 else ""
    manage_images_btn = edit_profile_btn = change_password_btn = ""
    if session.get("user") == pro["name"]:
        manage_images_btn = f'<a href="/manage-work-images/{pro["id"]}"><button>إدارة صور الأعمال</button></a>'
        edit_profile_btn = '<a href="/edit-profile"><button>تعديل المعلومات</button></a>'
        change_password_btn = '<a href="/change-password"><button>تغيير كلمة المرور</button></a>'

    comments_html = ""
    for c in comments:
        comments_html += f"""
        <div class="comment-box">
            <b>{c['commenter_name']}</b>
            <div class="rating-stars">{'★' * c['rating']}{'☆' * (5 - c['rating'])}</div>
            <div>{c['comment'] or ''}</div>
            <small>{c['created_at']}</small>
        </div>
        """

    whatsapp_link = build_whatsapp_link(pro["phone"])
    phone_btn = f'<a href="tel:{pro["phone"]}"><button>اتصال مباشر</button></a>' if pro["show_phone"] == 1 else ""
    whatsapp_btn = f'<a href="{whatsapp_link}" target="_blank"><button>واتساب مباشر</button></a>' if pro["show_whatsapp"] == 1 else ""

    return render_template_string(STYLE + settings_corner() + f"""
    <div class="container">
        <a href="/sections"><button>رجوع</button></a>
        {profile_block}
        <h2>{pro['name']}</h2>
        <div class="info-line"><b>الاختصاص:</b> {pro['section'] or '-'}</div>
        <div class="info-line"><b>المحافظة:</b> {pro['governorate'] or '-'}</div>
        <div class="info-line"><b>المدينة:</b> {pro['city'] or '-'}</div>
        <div class="info-line"><b>الخبرة:</b> {pro['exp'] or '-'}</div>
        <div class="info-line"><b>النبذة:</b> {pro['bio'] or '-'}</div>
        <div class="info-line"><b>التقييم:</b> {avg_rating} / 5 ({rating_count} تقييم)</div>

        <h3>صور الأعمال</h3>
        <div class="work-gallery">{gallery if gallery else '<div class="msg">لا توجد صور أعمال</div>'}</div>

        <div class="actions-row">
            {phone_btn}
            {whatsapp_btn}
        </div>
        <div class="actions-row">{chat_btn}</div>
        <div class="actions-row">{manage_images_btn}{edit_profile_btn}</div>
        <div class="actions-row">{change_password_btn}</div>
    </div>

    <div class="container">
        <h3>التقييمات والتعليقات</h3>
        {comments_html if comments_html else '<div class="msg">لا توجد تعليقات بعد</div>'}
    </div>

    {f'''<div class="container"><h3>أضف تقييمك</h3><form method="post"><select name="rating" required><option value="">اختر التقييم</option><option value="5">5 نجوم</option><option value="4">4 نجوم</option><option value="3">3 نجوم</option><option value="2">2 نجمتين</option><option value="1">1 نجمة</option></select><textarea name="comment" placeholder="اكتب تعليقك"></textarea><button>إرسال التقييم</button></form></div>''' if session.get('user') and session.get('user') != pro['name'] else ''}
    """)


# ================= إضافة صور جديدة للبروفايل =================
@app.route("/add-work-images/<int:user_id>", methods=["GET", "POST"])
def add_work_images(user_id):
    with get_db() as con:
        pro = con.execute("SELECT * FROM users WHERE id=? AND role='pro' AND is_verified=1", (user_id,)).fetchone()
    if not pro:
        return render_template_string(STYLE + settings_corner() + """<div class="container"><div class="msg">المهني غير موجود</div><a href="/sections"><button>رجوع</button></a></div>""")
    if session.get("user") != pro["name"]:
        return render_template_string(STYLE + settings_corner() + """<div class="container"><div class="msg">ليس لديك صلاحية إضافة صور لهذا البروفايل</div><a href="/sections"><button>رجوع</button></a></div>""")
    if request.method == "POST":
        work_files = request.files.getlist("work_images")
        new_names = []

        old_images = [img.strip() for img in pro["work_images"].split(",") if img.strip()] if pro["work_images"] else []
        valid_work_files = [wf for wf in work_files if wf and wf.filename]

        if len(old_images) + len(valid_work_files) > MAX_WORK_IMAGES:
            return render_template_string(STYLE + settings_corner() + f"""<div class="container"><div class="msg">الحد الأقصى لصور الأعمال هو {MAX_WORK_IMAGES} صور</div><a href="/profile/{user_id}"><button>رجوع</button></a></div>""")

        for wf in valid_work_files:
            valid_img, msg = validate_uploaded_image(wf)
            if not valid_img:
                return render_template_string(STYLE + settings_corner() + f"""<div class="container"><div class="msg">{msg}</div><a href="/profile/{user_id}"><button>رجوع</button></a></div>""")
            saved = save_uploaded_file(wf)
            if saved:
                new_names.append(saved)

        all_images = old_images + new_names
        with get_db() as con:
            con.execute("UPDATE users SET work_images=? WHERE id=?", (",".join(all_images), user_id))
            con.commit()
        return redirect(url_for("profile", user_id=user_id))
    return render_template_string(STYLE + settings_corner() + f"""<div class="container"><a href="/profile/{user_id}"><button>رجوع</button></a><h2>إضافة صور أعمال جديدة</h2><form method="post" enctype="multipart/form-data"><input type="file" name="work_images" multiple accept=".png,.jpg,.jpeg,.gif,.webp"><button>رفع الصور</button></form></div>""")


# ================= المحادثة =================
@app.route("/chat/<receiver_name>", methods=["GET", "POST"])
def chat(receiver_name):
    if "user" not in session:
        return redirect(url_for("login"))

    receiver_name = sanitize_input(receiver_name, 80)
    sender_name = session["user"]

    if sender_name == receiver_name:
        return render_template_string(STYLE + settings_corner() + """
        <div class="container"><div class="msg">لا يمكنك فتح محادثة مع نفسك</div><a href="/sections"><button>رجوع</button></a></div>
        """)

    with get_db() as con:
        cur = con.cursor()

        receiver = cur.execute("SELECT * FROM users WHERE name=?", (receiver_name,)).fetchone()
        if not receiver:
            return render_template_string(STYLE + settings_corner() + """
            <div class="container"><div class="msg">المستخدم غير موجود</div><a href="/sections"><button>رجوع</button></a></div>
            """)

        if receiver["allow_messages"] != 1:
            return render_template_string(STYLE + settings_corner() + """
            <div class="container"><div class="msg">هذا المستخدم أوقف استقبال الرسائل حالياً</div><a href="/sections"><button>رجوع</button></a></div>
            """)

        cur.execute(
            "UPDATE messages SET is_read=1 WHERE sender_name=? AND receiver_name=? AND is_read=0",
            (receiver_name, sender_name)
        )
        con.commit()

        if request.method == "POST":
            msg = sanitize_input(request.form.get("msg", ""), 1000)
            limit_key = f"{sender_name}::{receiver_name}"
            if too_many_attempts(MESSAGE_RATE_LIMIT, limit_key, MESSAGE_WINDOW_SECONDS, MESSAGE_MAX_COUNT):
                return render_template_string(STYLE + settings_corner() + """
                <div class="container"><div class="msg">أرسلت رسائل كثيرة بسرعة. حاول بعد قليل</div><a href="/inbox"><button>رجوع</button></a></div>
                """)
            if msg:
                cur.execute(
                    "INSERT INTO messages(sender_name, receiver_name, msg, is_read) VALUES(?,?,?,0)",
                    (sender_name, receiver_name, msg)
                )
                con.commit()

        msgs = cur.execute(
            "SELECT * FROM messages WHERE (sender_name=? AND receiver_name=?) OR (sender_name=? AND receiver_name=?) ORDER BY id ASC",
            (sender_name, receiver_name, receiver_name, sender_name)
        ).fetchall()

    html = ""
    for m in msgs:
        who = "أنا" if m["sender_name"] == sender_name else m["sender_name"]
        read_status = ""
        if m["sender_name"] == sender_name:
            read_status = '<div class="chat-status">✓ تمت القراءة</div>' if m["is_read"] == 1 else '<div class="chat-status">• تم الإرسال</div>'
        html += f'''
        <div class="chat-msg">
            <b>{who}:</b> {m["msg"]}
            <div class="chat-time">{m["created_at"]}</div>
            {read_status}
        </div>
        '''

    call_link = f"tel:{receiver['phone']}" if receiver and receiver["show_phone"] == 1 else "#"
    whatsapp_link = build_whatsapp_link(receiver['phone']) if receiver and receiver["show_whatsapp"] == 1 else "#"
    phone_btn = f'<a href="{call_link}"><button>اتصال مباشر</button></a>' if receiver and receiver["show_phone"] == 1 else ""
    whatsapp_btn = f'<a href="{whatsapp_link}" target="_blank"><button>واتساب مباشر</button></a>' if receiver and receiver["show_whatsapp"] == 1 else ""

    return render_template_string(STYLE + settings_corner() + f"""
    <div class="container">
        <a href="/sections"><button>رجوع</button></a>
        <h2>محادثة مع {receiver_name}</h2>
        <div class="actions-row">
            {phone_btn}
            {whatsapp_btn}
        </div>
    </div>
    <div class="chat-box">{html if html else '<div class="msg">لا توجد رسائل بعد</div>'}</div>
    <div class="container">
        <form method="post">
            <textarea name="msg" placeholder="اكتب رسالتك"></textarea>
            <button>إرسال</button>
        </form>
    </div>
    """)


# ================= صندوق الرسائل =================
@app.route("/inbox")
def inbox():
    if "user" not in session:
        return redirect(url_for("login"))

    me = session["user"]

    with get_db() as con:
        rows = con.execute("""
            SELECT sender_name, receiver_name, MAX(id) AS last_id
            FROM messages
            WHERE sender_name=? OR receiver_name=?
            GROUP BY sender_name, receiver_name
            ORDER BY last_id DESC
        """, (me, me)).fetchall()

        people = []
        for r in rows:
            other = r["receiver_name"] if r["sender_name"] == me else r["sender_name"]
            if other not in people:
                people.append(other)

        html = ""
        for person in people:
            last_msg = con.execute("""
                SELECT * FROM messages
                WHERE (sender_name=? AND receiver_name=?) OR (sender_name=? AND receiver_name=?)
                ORDER BY id DESC LIMIT 1
            """, (me, person, person, me)).fetchone()

            unread_count = con.execute("""
                SELECT COUNT(*) AS c FROM messages
                WHERE sender_name=? AND receiver_name=? AND is_read=0
            """, (person, me)).fetchone()["c"]

            snippet = last_msg["msg"][:60] if last_msg and last_msg["msg"] else ""
            created_at = last_msg["created_at"] if last_msg else ""

            unread_html = f'<div class="unread-badge">{unread_count} غير مقروءة</div>' if unread_count > 0 else ""

            html += f"""
            <div class="card">
                <b>{person}</b><br><br>
                <div>{snippet}</div>
                <small>{created_at}</small>
                {unread_html}
                <br><br>
                <a href="/chat/{person}"><button>فتح المحادثة</button></a>
            </div>
            """

    return render_template_string(STYLE + settings_corner() + f"""<div class="container"><a href="/sections"><button>رجوع</button></a><h2>الرسائل</h2></div>{html if html else '<div class="container"><div class="msg">لا توجد محادثات حالياً</div></div>'}""")


# ================= صفحة الإعدادات =================
@app.route("/settings")
def settings():
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE name=?", (session["user"],)).fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    account_status = "منشور" if user["is_verified"] == 1 else "بانتظار موافقة الأدمن"

    return render_template_string(STYLE + settings_corner() + f"""
    <div class="container">
        <a href="/sections"><button>رجوع</button></a>
        <h2>الإعدادات</h2>
        <div class="msg">هنا تگدر تتحكم بحسابك وبروفايلك داخل تطبيق المسطر</div>
    </div>

    <div class="settings-menu-card">
        <div class="settings-title">الحساب</div>

        <a class="settings-item" href="/edit-profile">
            حسابي
            <small>تعديل الاسم، الهاتف، البريد، المحافظة، المدينة والاختصاص</small>
        </a>

        <a class="settings-item" href="/change-password">
            تغيير كلمة المرور
            <small>تحديث كلمة المرور الخاصة بحسابك</small>
        </a>

        <a class="settings-item" href="/delete-account">
            حذف الحساب
            <small>حذف الحساب نهائياً من التطبيق</small>
        </a>
    </div>

    <div class="settings-menu-card">
        <div class="settings-title">البروفايل المهني</div>

        <a class="settings-item" href="/edit-profile">
            تعديل البروفايل
            <small>تعديل النبذة، الاختصاص، المحافظة، المدينة والخبرة</small>
        </a>

        <a class="settings-item" href="/manage-work-images/{user['id']}">
            الصور
            <small>إدارة صور الأعمال وإضافة أو حذف الصور</small>
        </a>

        <div class="settings-item">
            حالة الحساب
            <small>{account_status}</small>
        </div>
    </div>

    <div class="settings-menu-card">
        <div class="settings-title">الإشعارات</div>

        <div class="settings-item">
            إشعارات الرسائل
            <small>حالياً مرتبطة بصندوق الرسائل داخل التطبيق</small>
        </div>

        <div class="settings-item">
            إشعارات التقييمات
            <small>حالياً تظهر داخل البروفايل</small>
        </div>

        <div class="settings-item">
            إشعارات موافقة الأدمن
            <small>حالياً حالة الحساب تظهر من داخل الإعدادات</small>
        </div>
    </div>

    <div class="settings-menu-card">
        <div class="settings-title">الخصوصية</div>

        <a class="settings-item" href="/privacy-settings">
            إعدادات الخصوصية
            <small>إظهار أو إخفاء الهاتف، واتساب، واستلام الرسائل</small>
        </a>
    </div>

    <div class="settings-menu-card">
        <div class="settings-title">الدعم والمعلومات</div>

        <a class="settings-item" href="/contact-us">
            اتصل بنا
            <small>رقم الهاتف والبريد الإلكتروني</small>
        </a>

        <a class="settings-item" href="/about-app">
            حول التطبيق
            <small>معلومات عن تطبيق المسطر</small>
        </a>

        <a class="settings-item" href="/privacy-policy">
            سياسة الخصوصية
            <small>طريقة استخدام وحماية بيانات المستخدمين</small>
        </a>

        <a class="settings-item" href="/terms">
            شروط الاستخدام
            <small>شروط استخدام المنصة والخدمات</small>
        </a>
    </div>

    <div class="settings-menu-card">
        <div class="settings-title">الجلسة</div>

        <a class="settings-item" href="/logout">
            تسجيل خروج
            <small>الخروج من الحساب الحالي</small>
        </a>
    </div>
    """)


# ================= الخصوصية =================
@app.route("/privacy-settings", methods=["GET", "POST"])
def privacy_settings():
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE name=?", (session["user"],)).fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        show_phone = 1 if request.form.get("show_phone") == "1" else 0
        show_whatsapp = 1 if request.form.get("show_whatsapp") == "1" else 0
        allow_messages = 1 if request.form.get("allow_messages") == "1" else 0

        with get_db() as con:
            con.execute(
                "UPDATE users SET show_phone=?, show_whatsapp=?, allow_messages=? WHERE id=?",
                (show_phone, show_whatsapp, allow_messages, user["id"])
            )
            con.commit()

        return render_template_string(STYLE + settings_corner() + """
        <div class="container">
            <div class="msg">تم حفظ إعدادات الخصوصية بنجاح</div>
            <a href="/settings"><button>الرجوع للإعدادات</button></a>
        </div>
        """)

    return render_template_string(STYLE + settings_corner() + f"""
    <div class="container">
        <a href="/settings"><button>رجوع</button></a>
        <h2>إعدادات الخصوصية</h2>
        <form method="post">
            <label>إظهار رقم الهاتف</label>
            <select name="show_phone">
                <option value="1" {"selected" if user["show_phone"] == 1 else ""}>نعم</option>
                <option value="0" {"selected" if user["show_phone"] == 0 else ""}>لا</option>
            </select>

            <label>إظهار واتساب</label>
            <select name="show_whatsapp">
                <option value="1" {"selected" if user["show_whatsapp"] == 1 else ""}>نعم</option>
                <option value="0" {"selected" if user["show_whatsapp"] == 0 else ""}>لا</option>
            </select>

            <label>السماح بالرسائل</label>
            <select name="allow_messages">
                <option value="1" {"selected" if user["allow_messages"] == 1 else ""}>نعم</option>
                <option value="0" {"selected" if user["allow_messages"] == 0 else ""}>لا</option>
            </select>

            <button>حفظ الإعدادات</button>
        </form>
    </div>
    """)


# ================= صفحات المعلومات =================
@app.route("/about-app")
def about_app():
    return render_template_string(STYLE + settings_corner() + """
    <div class="container">
        <a href="/settings"><button>رجوع</button></a>
        <h2>حول التطبيق</h2>
        <div class="msg">
            المسطر هو تطبيق لعرض المهنيين والحرفيين والفنيين وتسهيل الوصول إليهم حسب الاختصاص والمحافظة والمدينة،
            مع دعم للبروفايل، الصور، التقييمات، الرسائل، وموافقة الأدمن قبل النشر.
        </div>
    </div>
    """)


@app.route("/privacy-policy")
def privacy_policy():
    return render_template_string(STYLE + settings_corner() + """
    <div class="container">
        <a href="/settings"><button>رجوع</button></a>
        <h2>سياسة الخصوصية</h2>
        <div class="msg">
            نحن نحافظ على بيانات المستخدمين داخل المنصة ونستخدمها فقط لتشغيل الحسابات، عرض البروفايلات،
            التواصل داخل التطبيق، وتحسين الخدمة. لا يتم استخدام بياناتك خارج غرض المنصة.
        </div>
    </div>
    """)


@app.route("/terms")
def terms():
    return render_template_string(STYLE + settings_corner() + """
    <div class="container">
        <a href="/settings"><button>رجوع</button></a>
        <h2>شروط الاستخدام</h2>
        <div class="msg">
            باستخدامك لتطبيق المسطر، أنت توافق على إدخال بيانات صحيحة، وعدم إساءة استخدام الرسائل أو التقييمات،
            وعدم نشر محتوى مخالف. للإدارة حق إيقاف أو حذف أي حساب مخالف.
        </div>
    </div>
    """)


# ================= اتصل بنا =================
@app.route("/contact-us")
def contact_us():
    whatsapp_contact_link = build_whatsapp_link(CONTACT_PHONE)
    return render_template_string(STYLE + settings_corner() + f"""
    <div class="container">
        <a href="/settings"><button>رجوع</button></a>
        <h2>اتصل بنا</h2>
        <div class="msg">تگدر تتواصل ويانه عبر الهاتف أو الإيميل</div>
    </div>

    <div class="contact-card">
        <h3>رقم الهاتف</h3>
        <div class="info-line">{CONTACT_PHONE}</div>
        <a href="tel:{CONTACT_PHONE}"><button>اتصال مباشر</button></a>
        <a href="{whatsapp_contact_link}" target="_blank"><button>واتساب</button></a>
    </div>

    <div class="contact-card">
        <h3>البريد الإلكتروني</h3>
        <div class="info-line">{CONTACT_EMAIL}</div>
        <a href="mailto:{CONTACT_EMAIL}"><button>إرسال إيميل</button></a>
    </div>
    """)


# ================= الأدمن =================
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        username = sanitize_input(request.form.get("u", ""), 80)
        password = request.form.get("p", "")
        with get_db() as con:
            admin_data = con.execute("SELECT * FROM admin_settings WHERE id=1").fetchone()
        if admin_data and username == admin_data["username"] and check_password_hash(admin_data["password"], password):
            session["admin"] = True
            session["admin_username"] = admin_data["username"]
            return redirect(url_for("dashboard"))
        return render_template_string(STYLE + """<div class="container"><div class="msg">بيانات دخول الأدمن غير صحيحة</div><a href="/admin"><button>رجوع</button></a></div>""")
    return render_template_string(STYLE + """<div class="container"><a href="/"><button>رجوع</button></a><h2>دخول الأدمن</h2><form method="post"><input name="u" placeholder="اسم المستخدم"><input type="password" name="p" placeholder="كلمة السر"><button>دخول</button></form></div>""")


@app.route("/admin-settings", methods=["GET", "POST"])
def admin_settings():
    if "admin" not in session:
        return redirect(url_for("admin"))
    with get_db() as con:
        admin_data = con.execute("SELECT * FROM admin_settings WHERE id=1").fetchone()
    if request.method == "POST":
        current_username = sanitize_input(request.form.get("current_username", ""), 80)
        current_password = request.form.get("current_password", "")
        new_username = sanitize_input(request.form.get("new_username", ""), 80)
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if current_username != admin_data["username"] or not check_password_hash(admin_data["password"], current_password):
            return render_template_string(STYLE + """<div class="container"><div class="msg">بيانات الأدمن الحالية غير صحيحة</div><a href="/admin-settings"><button>رجوع</button></a></div>""")
        if not new_username:
            return render_template_string(STYLE + """<div class="container"><div class="msg">اسم الأدمن الجديد مطلوب</div><a href="/admin-settings"><button>رجوع</button></a></div>""")
        final_password_hash = admin_data["password"]
        if new_password:
            if len(new_password) < 4:
                return render_template_string(STYLE + """<div class="container"><div class="msg">كلمة سر الأدمن الجديدة يجب أن تكون 4 أحرف أو أرقام على الأقل</div><a href="/admin-settings"><button>رجوع</button></a></div>""")
            if new_password != confirm_password:
                return render_template_string(STYLE + """<div class="container"><div class="msg">تأكيد كلمة السر الجديدة غير مطابق</div><a href="/admin-settings"><button>رجوع</button></a></div>""")
            final_password_hash = generate_password_hash(new_password)
        old_admin_username = admin_data["username"]
        with get_db() as con:
            con.execute("UPDATE admin_settings SET username=?, password=? WHERE id=1", (new_username, final_password_hash))
            con.commit()
        session["admin_username"] = new_username
        log_admin_action("تعديل بيانات الأدمن", old_admin_username, f"تم تغيير اسم الأدمن من {old_admin_username} إلى {new_username}")
        return render_template_string(STYLE + """<div class="container"><div class="msg">تم تحديث بيانات دخول الأدمن بنجاح</div><a href="/dashboard"><button>الرجوع للوحة التحكم</button></a></div>""")
    return render_template_string(STYLE + f"""<div class="container"><a href="/dashboard"><button>رجوع</button></a><h2>إعدادات الأدمن</h2><form method="post"><input name="current_username" placeholder="اسم الأدمن الحالي" required><input type="password" name="current_password" placeholder="كلمة السر الحالية" required><input name="new_username" value="{admin_data['username']}" placeholder="اسم الأدمن الجديد" required><input type="password" name="new_password" placeholder="كلمة سر جديدة (اتركها فارغة إذا ما تريد تغيرها)"><input type="password" name="confirm_password" placeholder="تأكيد كلمة السر الجديدة"><button>حفظ بيانات الأدمن</button></form></div>""")


@app.route("/admin-reset-user-password/<int:user_id>", methods=["GET", "POST"])
def admin_reset_user_password(user_id):
    if "admin" not in session:
        return redirect(url_for("admin"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return render_template_string(STYLE + """<div class="container"><div class="msg">المستخدم غير موجود</div><a href="/dashboard"><button>رجوع</button></a></div>""")
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not new_password or len(new_password) < 4:
            return render_template_string(STYLE + """<div class="container"><div class="msg">كلمة المرور الجديدة للمستخدم يجب أن تكون 4 أحرف أو أرقام على الأقل</div><a href="/dashboard"><button>رجوع</button></a></div>""")
        if new_password != confirm_password:
            return render_template_string(STYLE + """<div class="container"><div class="msg">تأكيد كلمة المرور للمستخدم غير مطابق</div><a href="/dashboard"><button>رجوع</button></a></div>""")
        with get_db() as con:
            con.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new_password), user_id))
            con.commit()
        log_admin_action("تعيين كلمة سر مستخدم", user["name"], "تم تعيين كلمة سر جديدة للمستخدم")
        return render_template_string(STYLE + f"""<div class="container"><div class="msg">تم تعيين كلمة سر جديدة للمستخدم: {user['name']}</div><a href="/dashboard"><button>الرجوع للوحة التحكم</button></a></div>""")
    return render_template_string(STYLE + f"""<div class="container"><a href="/dashboard"><button>رجوع</button></a><h2>تعيين كلمة سر جديدة للمستخدم</h2><div class="msg">المستخدم: {user['name']}</div><form method="post"><input type="password" name="new_password" placeholder="كلمة المرور الجديدة" required><input type="password" name="confirm_password" placeholder="تأكيد كلمة المرور الجديدة" required><button>حفظ كلمة المرور الجديدة</button></form></div>""")


@app.route("/dashboard")
def dashboard():
    if "admin" not in session:
        return redirect(url_for("admin"))
    search = sanitize_input(request.args.get("search", ""), 80)
    with get_db() as con:
        admin_data = con.execute("SELECT * FROM admin_settings WHERE id=1").fetchone()
        total_users = con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        total_pros = con.execute("SELECT COUNT(*) AS c FROM users WHERE role='pro'").fetchone()["c"]
        total_pending = con.execute("SELECT COUNT(*) AS c FROM users WHERE is_verified=0").fetchone()["c"]
        total_active = con.execute("SELECT COUNT(*) AS c FROM users WHERE is_verified=1").fetchone()["c"]
        if search:
            users = con.execute("SELECT * FROM users WHERE name LIKE ? OR phone LIKE ? ORDER BY id DESC", (f"%{search}%", f"%{search}%")).fetchall()
        else:
            users = con.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
        logs = con.execute("SELECT * FROM admin_logs ORDER BY id DESC LIMIT 20").fetchall()

    rows = ""
    for u in users:
        user_group = get_main_group_by_specialty(u["section"] or "")
        group_options = build_main_groups_options(user_group)
        specialty_options = build_specialties_options(u["section"] or "", user_group)
        rows += f"""
        <tr>
            <td>{u['name']}</td>
            <td>{u['phone']}</td>
            <td>{u['email']}</td>
            <td>{u['governorate'] or '-'}</td>
            <td>{u['city'] or '-'}</td>
            <td>{u['role']}</td>
            <td>{u['section'] or '-'}</td>
            <td>{'منشور' if u['is_verified'] == 1 else 'بانتظار الموافقة'}</td>
            <td>مشفرة</td>
            <td>
                <form action="/update_pro" method="post" style="display:inline">
                    <input type="hidden" name="id" value="{u['id']}">
                    <select name="main_group" id="main_group_{u['id']}" style="width:auto; padding:4px;" onchange="(function(){{const groups={json.dumps(SPECIALTY_GROUPS, ensure_ascii=False)}; const mg=document.getElementById('main_group_{u['id']}').value; const sec=document.getElementById('sect_{u['id']}'); sec.innerHTML=''; if(groups[mg]){{groups[mg].forEach(function(item){{const option=document.createElement('option'); option.value=item; option.textContent=item; sec.appendChild(option);}});}}}})()">{group_options}</select>
                    <select name="sect" id="sect_{u['id']}" style="width:auto; padding:4px;">{specialty_options}</select>
                    <button style="width:auto; padding:6px 10px; font-size:11px;">تغيير</button>
                </form>
            </td>
            <td>
                <a href="/approve/{u['id']}">{'إلغاء النشر' if u['is_verified']==1 else 'موافقة ونشر'}</a> |
                <a href="/admin-reset-user-password/{u['id']}">تعيين كلمة سر</a> |
                <a href="/del/{u['id']}" onclick="return confirm('حذف المستخدم؟')">حذف</a>
            </td>
        </tr>
        """

    logs_html = "".join([f"<tr><td>{log['admin_username']}</td><td>{log['action']}</td><td>{log['target_name'] or '-'}</td><td>{log['details'] or '-'}</td><td>{log['created_at']}</td></tr>" for log in logs])

    return render_template_string(STYLE + f"""
    <div class="container" style="width:95%">
        <h2>إدارة المستخدمين</h2>
        <div class="msg">اسم دخول الأدمن الحالي: {admin_data['username']}</div>
        <a href="/admin-settings"><button>تعديل اسم وكلمة سر الأدمن</button></a>
        <div class="work-gallery">
            <div class="card"><b>كل المستخدمين</b><br>{total_users}</div>
            <div class="card"><b>المهنيين</b><br>{total_pros}</div>
            <div class="card"><b>الحسابات المنشورة</b><br>{total_active}</div>
            <div class="card"><b>بانتظار الموافقة</b><br>{total_pending}</div>
        </div>
        <form method="get" style="margin-top:15px;"><input name="search" value="{search}" placeholder="ابحث بالاسم أو رقم الهاتف"><button>بحث</button></form>
        <table>
            <tr>
                <th>الاسم</th><th>الهاتف</th><th>البريد</th><th>المحافظة</th><th>المدينة</th>
                <th>النوع</th><th>الاختصاص</th><th>الحالة</th><th>كلمة المرور</th><th>تعديل الاختصاص</th><th>إجراءات</th>
            </tr>
            {rows}
        </table>
        <br>
        <h3>سجل نشاطات الأدمن</h3>
        <table>
            <tr><th>الأدمن</th><th>الإجراء</th><th>المستخدم</th><th>التفاصيل</th><th>الوقت</th></tr>
            {logs_html if logs_html else '<tr><td colspan="5">لا توجد نشاطات بعد</td></tr>'}
        </table>
        <br><a href="/logout"><button>تسجيل خروج</button></a>
    </div>
    """)


@app.route("/update_pro", methods=["POST"])
def update_pro():
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (request.form["id"],)).fetchone()
        new_section = sanitize_input(request.form.get("sect", ""), 80)
        if new_section not in SPECIALTIES:
            return redirect(url_for("dashboard"))
        con.execute("UPDATE users SET section=? WHERE id=?", (new_section, request.form["id"]))
        con.commit()
    if user:
        log_admin_action("تعديل اختصاص مستخدم", user["name"], f"تم تغيير الاختصاص إلى {new_section}")
    return redirect(url_for("dashboard"))


@app.route("/approve/<int:uid>")
def approve_user(uid):
    if "admin" not in session:
        return redirect(url_for("admin"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if user:
            new_status = 0 if user["is_verified"] == 1 else 1
            con.execute("UPDATE users SET is_verified=? WHERE id=?", (new_status, uid))
            con.commit()
            log_admin_action("موافقة/إلغاء نشر", user["name"], "تم نشر الحساب" if new_status == 1 else "تم إلغاء نشر الحساب")
    return redirect(url_for("dashboard"))


@app.route("/del/<int:uid>")
def delete_user(uid):
    if "admin" not in session:
        return redirect(url_for("admin"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if user:
            username = user["name"]
            if user["profile_pic"]:
                delete_file_if_exists(user["profile_pic"])
            if user["work_images"]:
                for img in [x.strip() for x in user["work_images"].split(",") if x.strip()]:
                    delete_file_if_exists(img)
            con.execute("DELETE FROM messages WHERE sender_name=? OR receiver_name=?", (username, username))
            con.execute("DELETE FROM comments WHERE user_id=?", (uid,))
            con.execute("DELETE FROM users WHERE id=?", (uid,))
            con.commit()
            log_admin_action("حذف مستخدم", username, "تم حذف المستخدم من لوحة الأدمن")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ================= إدارة صور الأعمال =================
@app.route("/manage-work-images/<int:user_id>", methods=["GET", "POST"])
def manage_work_images(user_id):
    with get_db() as con:
        pro = con.execute("SELECT * FROM users WHERE id=? AND role='pro'", (user_id,)).fetchone()
    if not pro:
        return render_template_string(STYLE + settings_corner() + """<div class="container"><div class="msg">المهني غير موجود</div><a href="/sections"><button>رجوع</button></a></div>""")
    if session.get("user") != pro["name"]:
        return render_template_string(STYLE + settings_corner() + """<div class="container"><div class="msg">ليس لديك صلاحية إدارة صور هذا البروفايل</div><a href="/sections"><button>رجوع</button></a></div>""")
    if request.method == "POST":
        action = request.form.get("action", "")
        old_images = [img.strip() for img in pro["work_images"].split(",") if img.strip()] if pro["work_images"] else []

        if action == "delete":
            image_name = request.form.get("image_name", "").strip()
            if image_name in old_images:
                old_images.remove(image_name)
                delete_file_if_exists(image_name)
                with get_db() as con:
                    con.execute("UPDATE users SET work_images=? WHERE id=?", (",".join(old_images), user_id))
                    con.commit()
                return redirect(url_for("manage_work_images", user_id=user_id))

        if action == "add":
            work_files = request.files.getlist("work_images")
            valid_work_files = [wf for wf in work_files if wf and wf.filename]

            if len(old_images) + len(valid_work_files) > MAX_WORK_IMAGES:
                return render_template_string(STYLE + settings_corner() + f"""<div class="container"><div class="msg">الحد الأقصى لصور الأعمال هو {MAX_WORK_IMAGES} صور</div><a href="/manage-work-images/{user_id}"><button>رجوع</button></a></div>""")

            new_names = []
            for wf in valid_work_files:
                valid_img, msg = validate_uploaded_image(wf)
                if not valid_img:
                    return render_template_string(STYLE + settings_corner() + f"""<div class="container"><div class="msg">{msg}</div><a href="/manage-work-images/{user_id}"><button>رجوع</button></a></div>""")
                saved = save_uploaded_file(wf)
                if saved:
                    new_names.append(saved)

            all_images = old_images + new_names
            with get_db() as con:
                con.execute("UPDATE users SET work_images=? WHERE id=?", (",".join(all_images), user_id))
                con.commit()
            return redirect(url_for("manage_work_images", user_id=user_id))

    with get_db() as con:
        pro = con.execute("SELECT * FROM users WHERE id=? AND role='pro'", (user_id,)).fetchone()

    gallery = ""
    if pro["work_images"]:
        images = [img.strip() for img in pro["work_images"].split(",") if img.strip()]
        for img in images:
            img_url = url_for("uploaded_file", filename=img)
            gallery += f"<div class=\"image-card\"><img src=\"{img_url}\" class=\"work-img-large\" alt=\"work\"><form method=\"post\"><input type=\"hidden\" name=\"action\" value=\"delete\"><input type=\"hidden\" name=\"image_name\" value=\"{img}\"><button class=\"small-btn\" style=\"background:red;color:white;\">حذف الصورة</button></form></div>"

    return render_template_string(STYLE + settings_corner() + f"""<div class="container"><a href="/profile/{user_id}"><button>رجوع</button></a><h2>إدارة صور الأعمال</h2><h3>إضافة صور جديدة</h3><form method="post" enctype="multipart/form-data"><input type="hidden" name="action" value="add"><input type="file" name="work_images" multiple accept=".png,.jpg,.jpeg,.gif,.webp"><button>رفع الصور</button></form><h3>الصور الحالية</h3><div class="work-gallery">{gallery if gallery else '<div class="msg">لا توجد صور أعمال حالياً</div>'}</div></div>""")


# ================= تغيير كلمة المرور =================
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user" not in session:
        return redirect(url_for("login"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE name=?", (session["user"],)).fetchone()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if request.method == "POST":
        current_pass = request.form.get("current_pass", "")
        new_pass = request.form.get("new_pass", "")
        confirm_pass = request.form.get("confirm_pass", "")
        if not check_password_hash(user["password"], current_pass):
            return render_template_string(STYLE + settings_corner() + """<div class="container"><div class="msg">كلمة المرور الحالية غير صحيحة</div><a href="/change-password"><button>رجوع</button></a></div>""")
        if not new_pass or len(new_pass) < 4:
            return render_template_string(STYLE + settings_corner() + """<div class="container"><div class="msg">كلمة المرور الجديدة يجب أن تكون 4 أحرف أو أرقام على الأقل</div><a href="/change-password"><button>رجوع</button></a></div>""")
        if new_pass != confirm_pass:
            return render_template_string(STYLE + settings_corner() + """<div class="container"><div class="msg">تأكيد كلمة المرور غير مطابق</div><a href="/change-password"><button>رجوع</button></a></div>""")
        with get_db() as con:
            con.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new_pass), user["id"]))
            con.commit()
        return render_template_string(STYLE + settings_corner() + """<div class="container"><div class="msg">تم تغيير كلمة المرور بنجاح</div><a href="/settings"><button>الرجوع للإعدادات</button></a></div>""")
    return render_template_string(STYLE + settings_corner() + """<div class="container"><a href="/settings"><button>رجوع</button></a><h2>تغيير كلمة المرور</h2><form method="post"><input type="password" name="current_pass" placeholder="كلمة المرور الحالية" required><input type="password" name="new_pass" placeholder="كلمة المرور الجديدة" required><input type="password" name="confirm_pass" placeholder="تأكيد كلمة المرور الجديدة" required><button>حفظ كلمة المرور</button></form></div>""")


# ================= حذف الحساب =================
@app.route("/delete-account", methods=["GET", "POST"])
def delete_account():
    if "user" not in session:
        return redirect(url_for("login"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE name=?", (session["user"],)).fetchone()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_text = request.form.get("confirm_text", "").strip()
        if not check_password_hash(user["password"], password):
            return render_template_string(STYLE + settings_corner() + """<div class="container"><div class="msg">كلمة المرور غير صحيحة</div><a href="/delete-account"><button>رجوع</button></a></div>""")
        if confirm_text != "احذف حسابي":
            return render_template_string(STYLE + settings_corner() + """<div class="container"><div class="msg">اكتب العبارة المطلوبة بشكل صحيح: احذف حسابي</div><a href="/delete-account"><button>رجوع</button></a></div>""")
        if user["profile_pic"]:
            delete_file_if_exists(user["profile_pic"])
        if user["work_images"]:
            for img in [x.strip() for x in user["work_images"].split(",") if x.strip()]:
                delete_file_if_exists(img)
        with get_db() as con:
            con.execute("DELETE FROM messages WHERE sender_name=? OR receiver_name=?", (user["name"], user["name"]))
            con.execute("DELETE FROM comments WHERE user_id=?", (user["id"],))
            con.execute("DELETE FROM users WHERE id=?", (user["id"],))
            con.commit()
        session.clear()
        return render_template_string(STYLE + """<div class="container"><div class="msg">تم حذف الحساب نهائياً</div><a href="/"><button>الصفحة الرئيسية</button></a></div>""")
    return render_template_string(STYLE + settings_corner() + """<div class="container"><a href="/settings"><button>رجوع</button></a><h2>حذف الحساب</h2><div class="msg">هذه العملية نهائية. اكتب كلمة المرور الحالية، ثم اكتب العبارة: احذف حسابي</div><form method="post"><input type="password" name="password" placeholder="كلمة المرور الحالية" required><input name="confirm_text" placeholder="اكتب هنا: احذف حسابي" required><button style="background:red;color:white;">تأكيد حذف الحساب</button></form></div>""")


# ================= تعديل البروفايل =================
@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE name=?", (session["user"],)).fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        name = sanitize_input(request.form.get("name", ""), 80)
        phone = normalize_iraq_phone(sanitize_input(request.form.get("phone", ""), 25))
        email = sanitize_input(request.form.get("email", ""), 120).lower()
        section = sanitize_input(request.form.get("section", ""), 80)
        governorate = sanitize_input(request.form.get("governorate", ""), 80)
        city = sanitize_input(request.form.get("city", ""), 80)
        exp = sanitize_input(request.form.get("exp", ""), 30)
        bio = sanitize_input(request.form.get("bio", ""), 500)

        if not name or not phone or not email:
            return render_template_string(
                STYLE + settings_corner() + """
                <div class="container">
                    <div class="msg">الاسم والهاتف والبريد الإلكتروني حقول مطلوبة</div>
                    <a href="/edit-profile"><button>رجوع</button></a>
                </div>
                """
            )

        if not valid_email(email):
            return render_template_string(
                STYLE + settings_corner() + """
                <div class="container">
                    <div class="msg">البريد الإلكتروني غير صحيح</div>
                    <a href="/edit-profile"><button>رجوع</button></a>
                </div>
                """
            )

        if not valid_phone(phone):
            return render_template_string(
                STYLE + settings_corner() + """
                <div class="container">
                    <div class="msg">رقم الهاتف غير صحيح</div>
                    <a href="/edit-profile"><button>رجوع</button></a>
                </div>
                """
            )

        if governorate and governorate not in IRAQ_GOVERNORATES:
            return render_template_string(
                STYLE + settings_corner() + """
                <div class="container">
                    <div class="msg">المحافظة غير صحيحة</div>
                    <a href="/edit-profile"><button>رجوع</button></a>
                </div>
                """
            )

        if section and section not in SPECIALTIES:
            return render_template_string(
                STYLE + settings_corner() + """
                <div class="container">
                    <div class="msg">الاختصاص غير صحيح</div>
                    <a href="/edit-profile"><button>رجوع</button></a>
                </div>
                """
            )

        with get_db() as con:
            cur = con.cursor()
            exists = cur.execute(
                "SELECT id FROM users WHERE (phone=? OR email=?) AND id != ?",
                (phone, email, user["id"])
            ).fetchone()

            if exists:
                return render_template_string(
                    STYLE + settings_corner() + """
                    <div class="container">
                        <div class="msg">رقم الهاتف أو البريد الإلكتروني مستخدم من حساب آخر</div>
                        <a href="/edit-profile"><button>رجوع</button></a>
                    </div>
                    """
                )

            new_profile_pic = user["profile_pic"]
            profile_file = request.files.get("profile_pic")

            if profile_file and profile_file.filename:
                valid_img, msg = validate_uploaded_image(profile_file)
                if not valid_img:
                    return render_template_string(
                        STYLE + settings_corner() + f"""
                        <div class="container">
                            <div class="msg">{msg}</div>
                            <a href="/edit-profile"><button>رجوع</button></a>
                        </div>
                        """
                    )

                saved_profile = save_uploaded_file(profile_file)
                if saved_profile:
                    if user["profile_pic"]:
                        delete_file_if_exists(user["profile_pic"])
                    new_profile_pic = saved_profile

            cur.execute(
                "UPDATE users SET name=?, phone=?, email=?, section=?, governorate=?, city=?, exp=?, bio=?, profile_pic=? WHERE id=?",
                (name, phone, email, section, governorate, city, exp, bio, new_profile_pic, user["id"])
            )
            con.commit()

        session["user"] = name
        return render_template_string(
            STYLE + settings_corner() + """
            <div class="container">
                <div class="msg">تم تحديث البروفايل بنجاح</div>
                <a href="/settings"><button>الرجوع للإعدادات</button></a>
            </div>
            """
        )

    profile_preview = (
        f'<img src="{url_for("uploaded_file", filename=user["profile_pic"])}" class="profile-img-large" alt="profile">'
        if user["profile_pic"]
        else '<div class="profile-placeholder-large">👤</div>'
    )

    selected_group = get_main_group_by_specialty(user["section"] or "")
    group_options = build_main_groups_options(selected_group)
    gov_options = build_governorates_options(user["governorate"] or "")
    specialty_options = build_specialties_options(user["section"] or "", selected_group)

    return render_template_string(
        STYLE + settings_corner() + f"""
        <div class="container">
            <a href="/settings"><button>رجوع</button></a>
            <h2>تعديل البروفايل</h2>
            {profile_preview}
            <form method="post" enctype="multipart/form-data">
                <input name="name" value="{user['name'] or ''}" placeholder="الاسم الكامل" required>
                <input name="phone" value="{user['phone'] or '+964'}" placeholder="+964XXXXXXXXXX" required>
                <input name="email" value="{user['email'] or ''}" placeholder="البريد الإلكتروني" required>

                <label>القسم الرئيسي</label>
                <select name="main_group" id="main_group" onchange="updateSpecialties()">
                    <option value="">اختر القسم الرئيسي</option>
                    {group_options}
                </select>

                <label>الاختصاص</label>
                <select name="section" id="section">{specialty_options}</select>

                <label>المحافظة</label>
                <select name="governorate" required>
                    <option value="">اختر المحافظة</option>
                    {gov_options}
                </select>

                <input name="city" value="{user['city'] or ''}" placeholder="المدينة / المنطقة">
                <input name="exp" value="{user['exp'] or ''}" placeholder="سنوات الخبرة">
                <textarea name="bio" placeholder="نبذة عنك">{user['bio'] or ''}</textarea>

                <label>تغيير الصورة الشخصية</label>
                <input type="file" name="profile_pic" accept=".png,.jpg,.jpeg,.gif,.webp">

                <button>حفظ التعديلات</button>
            </form>

            <a href="/change-password"><button>تغيير كلمة المرور</button></a>
            <a href="/manage-work-images/{user['id']}"><button>إدارة صور الأعمال</button></a>
            <a href="/delete-account"><button style="background:red;color:white;">حذف الحساب</button></a>
        </div>
        {specialty_script(user['section'] or '')}
        """
    )


if __name__ == "__main__":
    app.run()