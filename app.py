from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from random import randint
import secrets
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os
import re
import requests

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Configure the MySQL database connection
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure session to use filesystem (instead of signed cookies)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Session lifetime

# Configure Flask-Mail
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
mail = Mail(app)

# Initialize the SQLAlchemy database object
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate

# Define the User model
class User(db.Model):
    __tablename__ = 'users'  # Explicitly set the table name

    id = db.Column(db.Integer, primary_key=True)  # Primary key column
    username = db.Column(db.String(150, collation='utf8_bin'), nullable=False, unique=True)  # Username column with case-sensitive collation
    password = db.Column(db.String(150), nullable=False)  # Password column
    reset_token = db.Column(db.String(100), nullable=True)  # Reset token
    token_expiration = db.Column(db.DateTime, nullable=True)  # Token expiration time

    def __repr__(self):
        return f'<User {self.username}>'

# Function to validate email address
def is_valid_email(email):
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(regex, email)

# Route to render the login page
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('homepage'))
    return render_template('form.html')  # Render your HTML form page

# Route to render the login page directly
@app.route('/login_page')
def login_page():
    return render_template('form.html', show_login=True)

# Route to handle the login form submission
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    remember = request.form.get('remember')

    if username and password:
        # Authenticate user
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            if remember:
                session.permanent = True  # Make the session permanent
            else:
                session.permanent = False  # Make the session non-permanent
            return redirect(url_for('homepage'))  # Redirect to homepage after successful login
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login_page'))  # Redirect to login page with error
    else:
        flash('Please enter both username and password.', 'error')
        return redirect(url_for('login_page'))  # Redirect to login page with error
    
# Function to check if the email exists
def is_existing_email(email):
    api_key = os.getenv('EMAIL_VALIDATION_API_KEY')  # Add your API key to .env
    api_url = f"https://emailvalidation.abstractapi.com/v1/?api_key={api_key}&email={email}"
    
    try:
        response = requests.get(api_url)
        response_data = response.json()
        if response.status_code == 200:
            return response_data.get('is_valid_format', {}).get('value', False) and response_data.get('deliverability') == "DELIVERABLE"
        else:
            return False  # Treat non-200 responses as invalid email
    except Exception as e:
        print(f"Email validation error: {e}")
        return False

# Route to handle the sign-up form submission
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    password = request.form.get('password')

    if username and password:
        if not is_valid_email(username):
            flash('Invalid email address.', 'error')
            return redirect(url_for('index'))  # Redirect to signup page with error

        if not is_existing_email(username):
            flash('The email address does not exist or cannot receive emails.', 'error')
            return redirect(url_for('index'))  # Redirect to signup page with error

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('index'))  # Redirect to signup page with error

        # Create a new user with the submitted username and hashed password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        session['username'] = username
        return redirect(url_for('homepage'))  # Redirect to homepage after successful sign-up
    else:
        flash('Please enter both username and password.', 'error')
        return redirect(url_for('index'))  # Redirect to signup page with error
# Route to handle logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# Route to render the forgot password page and handle form submission
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        otp = request.form.get('otp')

        user = User.query.filter_by(username=username).first()
        if user:
            if otp:
                if user.reset_token == otp and user.token_expiration > datetime.utcnow():
                    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                    user.password = hashed_password
                    user.reset_token = None
                    user.token_expiration = None
                    db.session.commit()
                    flash('Password reset successful! You can now log in.', 'success')
                    return redirect(url_for('login_page'))
                else:
                    flash('Invalid or expired OTP.', 'error')
                    return render_template('forgot_password.html', username=username, show_reset=True)
            else:
                otp = str(randint(100000, 999999))
                user.reset_token = otp
                user.token_expiration = datetime.utcnow() + timedelta(minutes=10)
                db.session.commit()
                send_otp_email(user.username, otp)
                flash('OTP has been sent to your email.', 'success')
                return render_template('forgot_password.html', username=username, show_reset=True)
        else:
            flash('Username not found.', 'error')
            return render_template('forgot_password.html', show_reset=False)
    return render_template('forgot_password.html', show_reset=False)

def send_otp_email(username, otp):
    user = User.query.filter_by(username=username).first()
    if user and is_valid_email(user.username):
        msg = Message(
            "Your OTP for Password Reset",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[user.username]
        )
        msg.body = f"Your OTP for password reset is: {otp}"
        mail.send(msg)

# Route to handle password reset via token
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if user and user.token_expiration > datetime.utcnow():
        if request.method == 'POST':
            password = request.form.get('password')
            if password:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                user.password = hashed_password
                user.reset_token = None
                user.token_expiration = None
                db.session.commit()
                flash('Password reset successful! You can now log in.', 'success')
                return redirect(url_for('login_page'))
            else:
                flash('Please enter a new password.', 'error')
        return render_template('forgot_password.html', token=token, show_reset=True)
    else:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('forgot_password'))

# Route to render the homepage after login or sign-up
@app.route('/homepage')
def homepage():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('homepage.html', username=session['username'])

# Main entry point of the app
if __name__ == '__main__':
    app.run(debug=True)