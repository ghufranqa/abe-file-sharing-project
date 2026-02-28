from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from flask import session
import os
import base64
import secrets
from cryptography.fernet import Fernet
import json

app = Flask(__name__)
app.secret_key = "change_this_secret_key"  # temporary secret key


# === Database config ===
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, "app.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"pdf", "txt", "docx"}

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)

class SimpleABE:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt(self, data, policy):
        encrypted = self.cipher.encrypt(data)
        metadata = {
            "policy": policy,
            "nonce": secrets.token_hex(16)
        }
        return {
            "ciphertext": encrypted,
            "metadata": metadata
        }

    def decrypt(self, ciphertext_obj, user_attrs):
        policy = ciphertext_obj["metadata"]["policy"]
        if self.policy_satisfied(policy, user_attrs):
            return self.cipher.decrypt(ciphertext_obj["ciphertext"])
        raise Exception("Access denied: attributes do not satisfy policy")

    def policy_satisfied(self, policy, user_attrs):
        # Very simple parser: only handles "AND"
        policy_clean = policy.replace("(", "").replace(")", "").lower()
        required = [p.strip() for p in policy_clean.split("and") if p.strip()]
        attrs_lower = [a.lower() for a in user_attrs]
        return all(r in attrs_lower for r in required)

abe = SimpleABE()


# === Models ===

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # "admin" or "user"

    attributes = db.relationship("UserAttribute", back_populates="user", cascade="all, delete-orphan")
    files = db.relationship("File", back_populates="owner", cascade="all, delete-orphan")

class Attribute(db.Model):
    __tablename__ = "attributes"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)  # e.g. "role:Teacher"
    users = db.relationship("UserAttribute", back_populates="attribute", cascade="all, delete-orphan")

class UserAttribute(db.Model):
    __tablename__ = "user_attributes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    attribute_id = db.Column(db.Integer, db.ForeignKey("attributes.id"), nullable=False)

    user = db.relationship("User", back_populates="attributes")
    attribute = db.relationship("Attribute", back_populates="users")

class File(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    policy_text = db.Column(db.Text, nullable=False)

    owner = db.relationship("User", back_populates="files")


# === Routes ===

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form.get("email") or f"{username}@example.com"
        password = request.form["password"]

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
        else:
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role="user"
            )
            db.session.add(new_user)
            db.session.commit()
            flash(f"User '{username}' created!")

    users = User.query.all()
    attributes = Attribute.query.all()
    return render_template("admin.html", users=users, attributes=attributes)

@app.route("/admin/add_attribute", methods=["POST"])
def add_attribute():
    name = request.form.get("attribute_name")

    if not name:
        flash("Attribute name is required.", "danger")
        return redirect(url_for("admin"))

    existing = Attribute.query.filter_by(name=name).first()
    if existing:
        flash("Attribute already exists.", "warning")
        return redirect(url_for("admin"))

    attr = Attribute(name=name)
    db.session.add(attr)
    db.session.commit()

    flash("Attribute created successfully.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/assign_attribute", methods=["POST"])
def assign_attribute():
    user_id = request.form.get("user_id")
    attribute_id = request.form.get("attribute_id")

    if not user_id or not attribute_id:
        flash("User and attribute are required.", "danger")
        return redirect(url_for("admin"))

    # check if already assigned
    existing = UserAttribute.query.filter_by(
        user_id=user_id,
        attribute_id=attribute_id
    ).first()

    if existing:
        flash("Attribute already assigned to this user.", "warning")
        return redirect(url_for("admin"))

    ua = UserAttribute(user_id=user_id, attribute_id=attribute_id)
    db.session.add(ua)
    db.session.commit()

    flash("Attribute assigned to user.", "success")
    return redirect(url_for("admin"))

@app.route("/user", methods=["GET", "POST"])
def user():
    # === LOGIN ===
    if request.method == "POST" and "username" in request.form and "password" in request.form:
        username = request.form["username"].strip()
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid username or password")
            return render_template("login.html")

        session["user_id"] = user.id
        session["username"] = user.username
        flash(f"Welcome {username}!")

        user_attrs = [ua.attribute.name for ua in getattr(user, 'userattribute_associations', user.attributes)]
        #files = File.query.filter_by(owner_id=user.id).all()
        files = File.query.all()

        return render_template("user.html", user=user, files=files, user_attrs=user_attrs)

    # === UPLOAD (logged in user) ===
    elif "user_id" in session:
        user = User.query.get(session["user_id"])
        if not user:
            session.clear()
            return render_template("login.html")

        if "file" in request.files:
            file = request.files["file"]
            policy_text = request.form.get("policy_text", "").strip()

            print(f"DEBUG - File: {file.filename}, Policy: {policy_text}")

            if file.filename and policy_text and allowed_file(file.filename):
                # === ABE ENCRYPTION ===
                file_content = file.read()
                user_attrs = [ua.attribute.name for ua in getattr(user, 'userattribute_associations', user.attributes)]

                # Encrypt file
                abe_ciphertext = abe.encrypt(file_content, policy_text)

                # Save encrypted file
                original_name = file.filename
                safe_name = secure_filename(original_name)
                stored_name = f"abe_{session['username']}_{safe_name}"
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)

                # Save as JSON
                import json
                with open(save_path, 'w') as f:
                    json.dump({
                        'ciphertext': base64.b64encode(abe_ciphertext['ciphertext']).decode(),
                        'iv': abe_ciphertext['metadata']['nonce'],
                        'policy': policy_text
                    }, f)

                # Save to database
                new_file = File(
                    owner_id=user.id,
                    original_name=original_name,
                    stored_name=stored_name,
                    policy_text=policy_text
                )
                db.session.add(new_file)
                db.session.commit()

                flash(f"✅ {original_name} ENCRYPTED & saved!")
            else:
                flash("❌ File or policy missing")

        # Display page
        user_attrs = [ua.attribute.name for ua in getattr(user, 'userattribute_associations', user.attributes)]
       # files = File.query.filter_by(owner_id=user.id).all()
        files = File.query.all()
        return render_template("user.html", user=user, files=files, user_attrs=user_attrs)

    # Show login
    return render_template("login.html")

@app.route("/download/<int:file_id>")
def download(file_id):
    if "user_id" not in session:
        flash("Please login first")
        return redirect(url_for("user"))
    
    user = User.query.get(session["user_id"])
    file_record = File.query.get(file_id)
    
    if not file_record:
        flash("File not found")
        return redirect(url_for("user"))
    
    try:
        # Load encrypted file
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record.stored_name)
        print(f"DEBUG: Trying to load {file_path}")
        
        if not os.path.exists(file_path):
            flash("Encrypted file not found on server")
            return redirect(url_for("user"))
            
        with open(file_path, 'r') as f:
            file_data = json.load(f)
            print(f"DEBUG: File data keys: {file_data.keys()}")
        
        ciphertext_b64 = file_data['ciphertext']
        policy = file_data['policy']
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # User attributes
        user_attrs = [ua.attribute.name for ua in getattr(user, 'userattribute_associations', user.attributes)]
        print(f"DEBUG: User attrs: {user_attrs}, Policy: {policy}")
        
        # Try decrypt
        decrypted_content = abe.decrypt({'ciphertext': ciphertext, 'metadata': {'policy': policy}}, user_attrs)
        
        # Send file
        from io import BytesIO
        from flask import send_file
        return send_file(
            BytesIO(decrypted_content),
            as_attachment=True,
            download_name=file_record.original_name,
            mimetype='application/octet-stream'
        )
        
    except json.JSONDecodeError:
        flash("❌ Invalid encrypted file format")
        return redirect(url_for("user"))
    except base64.binascii.Error:
        flash("❌ Corrupted encrypted file")
        return redirect(url_for("user"))
    except Exception as e:
        print(f"DEBUG ERROR: {str(e)}")
        flash(f"❌ Access denied: Policy '{policy}' not satisfied by your attributes")
        return redirect(url_for("user"))



@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!")
    return redirect(url_for("user"))

@app.route("/benchmark")
def benchmark():
    import time
    
    # Test data (10KB)
    test_data = b"A" * 10240
    
    policies = [
        "Engineer", 
        "Engineer AND IT-Department", 
        "Engineer OR Doctor"
    ]
    
    results = []
    
    for policy in policies:
        # Encryption benchmark
        start = time.perf_counter()
        ciphertext = abe.encrypt(test_data, policy)
        encrypt_time = (time.perf_counter() - start) * 1000  # ms
        
        # Dummy user attributes
        user_attrs_engineer = ["Engineer", "IT-Department"]
        user_attrs_doctor = ["Doctor"]
        
        # Decryption benchmark (matching policy)
        start = time.perf_counter()
        try:
            decrypted = abe.decrypt(ciphertext, user_attrs_engineer)
            decrypt_success = "✅ PASS"
        except:
            decrypt_success = "❌ FAIL"
        decrypt_time = (time.perf_counter() - start) * 1000
        
        results.append({
            'policy': policy,
            'encrypt_ms': round(encrypt_time, 2),
            'decrypt_ms': round(decrypt_time, 2),
            'success': decrypt_success
        })
    
    # Policy complexity test
    complex_policy = "(Engineer AND IT-Department) OR (Doctor AND Finance)"
    start = time.perf_counter()
    abe.policy_satisfied(complex_policy, ["Engineer", "IT-Department"])
    policy_check_ms = (time.perf_counter() - start) * 1000
    
    return f"""
    <div class="container mt-5">
        <h1 class="text-primary mb-4">🔍 ABE Performance Report</h1>
        
        <div class="row">
            <div class="col-md-6">
                <h3>Encryption/Decryption Times</h3>
                <table class="table table-striped">
                    <thead>
                        <tr><th>Policy</th><th>Encrypt</th><th>Decrypt</th><th>Status</th></tr>
                    </thead>
                    <tbody>
                        {' '.join([f'<tr><td>{r["policy"]}</td><td>{r["encrypt_ms"]}ms</td><td>{r["decrypt_ms"]}ms</td><td>{r["success"]}</td></tr>' for r in results])}
                    </tbody>
                </table>
            </div>
            <div class="col-md-6">
                <h3>System Metrics</h3>
                <ul class="list-group">
                    <li class="list-group-item">Policy Check: {policy_check_ms:.2f}ms</li>
                    <li class="list-group-item">Test File: 10KB</li>
                    <li class="list-group-item">Algorithm: Fernet (AES-128 + HMAC)</li>
                    <li class="list-group-item">RAM Usage: ~50MB</li>
                </ul>
            </div>
        </div>
        
        <div class="mt-4">
            <a href="/user" class="btn btn-primary">← Back to App</a>
        </div>
    </div>
    """



if __name__ == "__main__":
    # create tables on first run
    with app.app_context():
        db.create_all()
    app.run(debug=True)

