from flask import Flask, render_template_string, request, redirect, url_for, flash, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, secrets, uuid, datetime, random
import pdfkit

# --- CONFIG ---
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# OAuth placeholders
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='YOUR_GOOGLE_CLIENT_ID',
    client_secret='YOUR_GOOGLE_CLIENT_SECRET',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
)
facebook = oauth.register(
    name='facebook',
    client_id='YOUR_FACEBOOK_APP_ID',
    client_secret='YOUR_FACEBOOK_APP_SECRET',
    access_token_url='https://graph.facebook.com/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email'},
)

# --- DATABASE ---
def db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# --- USER CLASS ---
class User(UserMixin):
    def __init__(self, id, email, mobile=None, points=0):
        self.id = id
        self.email = email
        self.mobile = mobile
        self.points = points

@login_manager.user_loader
def load_user(user_id):
    con = db()
    u = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    con.close()
    if u:
        return User(id=u["id"], email=u["email"], mobile=u["mobile"], points=u["points"])
    return None

# --- UTILITIES ---
waste_info = {
    "Plastic": {
        "decompose": "400 years",
        "process": "Recycle or reduce use",
        "material": "Polyethylene / PET",
        "extract": "Can be melted and reshaped into new plastic products"
    },
    "Organic": {
        "decompose": "2-6 months",
        "process": "Compost or feed animals",
        "material": "Food scraps, leaves",
        "extract": "Nutrient-rich compost/fertilizer"
    },
    "Metal": {
        "decompose": "50-100 years",
        "process": "Collect and melt",
        "material": "Aluminum, steel, copper",
        "extract": "Metal for new tools/objects"
    },
    "Glass": {
        "decompose": "1 million years",
        "process": "Collect and recycle",
        "material": "Silica, soda ash, limestone",
        "extract": "Can be remelted into bottles or glassware"
    }
}

def save_file(file):
    ext = os.path.splitext(file.filename)[1]
    filename = str(uuid.uuid4()) + ext
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)
    return path

def predict_waste(file_path):
    """Mock ML prediction: returns (waste_type, confidence)"""
    waste_types = ["Plastic", "Organic", "Metal", "Glass"]
    waste = random.choice(waste_types)
    confidence = round(random.uniform(0.7, 0.99), 2)
    return waste, confidence

def generate_pdf(report):
    info = waste_info.get(report['waste_type'], {})
    html = f"""
    <h1>Waste Report</h1>
    <p>User ID: {report['user_id']}</p>
    <p>Waste Type: {report['waste_type']} ({report['confidence']*100}%)</p>
    <p>Decomposition Time: {info.get('decompose','Unknown')}</p>
    <p>Process: {info.get('process','Unknown')}</p>
    <p>Material: {info.get('material','Unknown')}</p>
    <p>Extractable: {info.get('extract','Unknown')}</p>
    <p>Lat: {report['lat']}</p>
    <p>Lon: {report['lon']}</p>
    <p>Note: {report['note']}</p>
    <p>Status: {report['status']}</p>
    <p>Timestamp: {report['timestamp']}</p>
    """
    pdf_path = os.path.join(UPLOAD_FOLDER, f"report_{report['id']}.pdf")
    pdfkit.from_string(html, pdf_path)
    return pdf_path

def get_leaderboard(con):
    return con.execute("SELECT email, points FROM users ORDER BY points DESC LIMIT 5").fetchall()

# --- AI CHAT FUNCTION ---
def ask_gemini(question, waste_type=None):
    """Mock AI response for testing"""
    if waste_type:
        return f"About {waste_type}: {question}? You can recycle it according to standard methods. Decompose time depends on material."
    return f"AI Answer: {question}? Handle waste properly or recycle it."

# --- ROUTES ---

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    result = confidence = decompose = process = material = extract = None
    if request.method == "POST":
        file = request.files["image"]
        path = save_file(file)
        result, confidence = predict_waste(path)

        lat = request.form.get("lat")
        lon = request.form.get("lon")
        note = request.form.get("note", "")
        input_method = request.form.get("input_method", "gallery")

        info = waste_info.get(result, {})
        decompose = info.get("decompose")
        process = info.get("process")
        material = info.get("material")
        extract = info.get("extract")

        con = db()
        con.execute(
            "INSERT INTO reports (user_id, waste_type, confidence, lat, lon, note, input_method, timestamp, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (current_user.id, result, confidence, lat, lon, note, input_method, datetime.datetime.now(), "Pending")
        )
        con.execute("UPDATE users SET points = points + 10 WHERE id=?", (current_user.id,))
        con.commit()
        con.close()
        flash("Report submitted successfully!")

    return render_template_string("""
    <h2>Upload Waste Image</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}<ul>{% for m in messages %}<li>{{m}}</li>{% endfor %}</ul>{% endif %}{% endwith %}
    <form method="post" enctype="multipart/form-data">
      Input Method:
      <select name="input_method">
        <option value="camera">Camera</option>
        <option value="gallery" selected>Gallery</option>
      </select><br>
      Image: <input type="file" name="image" required><br>
      Latitude: <input type="text" name="lat"><br>
      Longitude: <input type="text" name="lon"><br>
      Note: <input type="text" name="note"><br>
      <input type="submit" value="Submit">
    </form>
    {% if result %}
      <h3>Prediction Result</h3>
      <p>Waste Type: {{result}} (Confidence: {{confidence}})</p>
      <p>Decomposition Time: {{decompose}}</p>
      <p>Process: {{process}}</p>
      <p>Material: {{material}}</p>
      <p>Extractable: {{extract}}</p>
    {% endif %}
    <a href="{{ url_for('dashboard') }}">Dashboard</a> | <a href="{{ url_for('logout') }}">Logout</a>
    """, result=result, confidence=confidence, decompose=decompose, process=process, material=material, extract=extract)

@app.route("/dashboard")
@login_required
def dashboard():
    con = db()
    reports = con.execute("SELECT * FROM reports WHERE user_id=?", (current_user.id,)).fetchall()
    leaderboard = get_leaderboard(con)
    con.close()
    return render_template_string("""
    <h2>Dashboard</h2>
    <h3>Your Reports</h3>
    <ul>
      {% for r in reports %}
        <li>{{r['waste_type']}} ({{r['confidence']*100}}%) - {{r['status']}} - <a href="{{ url_for('download_report', report_id=r['id']) }}">PDF</a></li>
      {% endfor %}
    </ul>
    <h3>Leaderboard</h3>
    <ul>
      {% for l in leaderboard %}
        <li>{{l['email']}} - {{l['points']}} pts</li>
      {% endfor %}
    </ul>

    <h3>Ask AI about your Waste</h3>
    <select id="waste_type">
      <option value="">Select Waste Type (Optional)</option>
      <option value="Plastic">Plastic</option>
      <option value="Organic">Organic</option>
      <option value="Metal">Metal</option>
      <option value="Glass">Glass</option>
    </select><br>
    <textarea id="question" placeholder="Type your question..." rows="2" cols="50"></textarea><br>
    <button onclick="sendQuestion()">Ask AI</button>
    <div id="chatbox" style="border:1px solid #ccc; padding:10px; margin-top:10px; max-height:200px; overflow:auto;"></div>

    <script>
    function sendQuestion(){
        let question = document.getElementById('question').value;
        let waste_type = document.getElementById('waste_type').value;
        if(!question){ alert("Type a question!"); return; }
        fetch("/chat", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({question: question, waste_type: waste_type})
        })
        .then(res => res.json())
        .then(data => {
            let chatbox = document.getElementById('chatbox');
            chatbox.innerHTML += "<b>You:</b> "+question+"<br><b>AI:</b> "+data.answer+"<br><hr>";
            document.getElementById('question').value = "";
        });
    }
    </script>

    <a href="{{ url_for('index') }}">New Report</a> | <a href="{{ url_for('logout') }}">Logout</a>
    """, reports=reports, leaderboard=leaderboard)

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    data = request.get_json()
    question = data.get("question")
    waste_type = data.get("waste_type")
    if not question:
        return jsonify({"answer": "Please ask a valid question."})
    answer = ask_gemini(question, waste_type)
    return jsonify({"answer": answer})

@app.route("/admin")
@login_required
def admin():
    if current_user.email != "admin@example.com":
        flash("Access denied")
        return redirect(url_for("index"))
    con = db()
    reports = con.execute("SELECT r.*, u.email FROM reports r JOIN users u ON r.user_id=u.id").fetchall()
    con.close()
    return render_template_string("""
    <h2>Admin Panel</h2>
    <ul>
    {% for r in reports %}
      <li>{{r['email']}} - {{r['waste_type']}} ({{r['confidence']*100}}%) - {{r['status']}}
        - <a href="{{ url_for('approve', report_id=r['id']) }}">Approve</a>
        - <a href="{{ url_for('download_report', report_id=r['id']) }}">PDF</a>
      </li>
    {% endfor %}
    </ul>
    <a href="{{ url_for('index') }}">Home</a>
    """, reports=reports)

@app.route("/approve/<int:report_id>")
@login_required
def approve(report_id):
    if current_user.email != "admin@example.com":
        flash("Access denied")
        return redirect(url_for("index"))
    con = db()
    con.execute("UPDATE reports SET status='Approved' WHERE id=?", (report_id,))
    con.commit()
    con.close()
    flash("Report approved!")
    return redirect(url_for("admin"))

@app.route("/download_report/<int:report_id>")
@login_required
def download_report(report_id):
    con = db()
    report = con.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
    con.close()
    if report:
        pdf_path = generate_pdf(report)
        return send_file(pdf_path, as_attachment=True)
    flash("Report not found")
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        con = db()
        user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        con.close()
        if user and check_password_hash(user["password"], password):
            login_user(User(id=user["id"], email=user["email"], mobile=user["mobile"], points=user["points"]))
            return redirect(url_for("index"))
        flash("Invalid credentials")
    return render_template_string("""
    <h2>Login</h2>
    {% with messages = get_flashed_messages() %}{% if messages %}<ul>{% for m in messages %}<li>{{m}}</li>{% endfor %}</ul>{% endif %}{% endwith %}
    <form method="post">
      Email: <input type="email" name="email"><br>
      Password: <input type="password" name="password"><br>
      <input type="submit" value="Login">
    </form>
    <a href="{{ url_for('register') }}">Register</a>
    """)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        mobile = request.form.get("mobile")
        password = generate_password_hash(request.form.get("password"))
        con = db()
        con.execute("INSERT INTO users (email, mobile, password, points) VALUES (?, ?, ?, ?)",
                    (email, mobile, password, 0))
        con.commit()
        con.close()
        flash("Registration successful")
        return redirect(url_for("login"))
    return render_template_string("""
    <h2>Register</h2>
    <form method="post">
      Email: <input type="email" name="email"><br>
      Mobile: <input type="text" name="mobile"><br>
      Password: <input type="password" name="password"><br>
      <input type="submit" value="Register">
    </form>
    <a href="{{ url_for('login') }}">Login</a>
    """)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# --- OAuth routes placeholders (Google / Facebook) ---
# ... same as previous code for Google/Facebook

# --- INIT DATABASE ---
if __name__ == "__main__":
    con = db()
    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            mobile TEXT,
            password TEXT,
            points INTEGER DEFAULT 0
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            waste_type TEXT,
            confidence REAL,
            lat TEXT,
            lon TEXT,
            note TEXT,
            input_method TEXT,
            timestamp DATETIME,
            status TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    con.commit()
    con.close()
    app.run(debug=True)
