import os
from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
                        login_required, current_user 
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

app = Flask(__name__, 
            template_folder="platform/templates",
            static_folder="platform/static"
)

# Fetch credentials from environment variables (with fallbacks for local dev)
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "password")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "tnt_auth")

app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}"
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "super-secret-default-key")

# Extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
bcrypt = Bcrypt(app)

# User Model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    role = db.Column(db.String(50), default="user", nullable=False)

# Initialize database
with app.app_context():
    db.create_all()

# User loader - required by Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# ROUTE - Registration
@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        hashed_password = bcrypt.generate_password_hash(
            request.form.get("password")
        ).decode('utf-8')

        user = Users(
            username=request.form.get("username"),
            password=hashed_password,
            role="user"
        )

        db.session.add(user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("auth/register.html")

# ROUTE - Login
@app.route('/login', methods=["GET", "POST"])
def login():

    if request.method == "POST":
        user = Users.query.filter_by(
            username=request.form.get("username")
        ).first()
        
        if user and bcrypt.check_password_hash(
        user.password, request.form.get("password")
            ):
                login_user(user)

                # Redirection
                if user.role == "admin":
                    return redirect(url_for("admin_dashboard"))
                else:
                    return redirect(url_for("user_dashboard"))
    return render_template("auth/login.html")

# ROUTE - Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ROUTE - User Dashboard
@app.route('/userdashboard')
@login_required
def user_dashboard():
    return render_template("dashboards/userdashboard.html")

# ROUTE - Admin Dashboard
@app.route('/admindashboard')
@login_required
def admin_dashboard():
    return render_template("dashboards/admindashboard.html")

# Protected home route
@app.route('/')
@login_required # Only logged-in users can access
def home():
    return render_template("home.html")

if __name__ == "__main__":
    app.run(debug=True)