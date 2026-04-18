import os
from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)

# --- MANDATORY SECURITY RULES APPLIED ---
# 1. Never set debug=True in production
app.config['DEBUG'] = False

# 2. Never hardcode secrets - pull from environment
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ph = PasswordHasher()

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # 7. Use Argon2 for password hashing
    password_hash = db.Column(db.String(255), nullable=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Basic validation (8. Input is escaped by Jinja2 during rendering)
        if not username or not password:
            flash("All fields are required.")
            return redirect(url_for('register'))

        # Check if user exists using SQLAlchemy's ORM 
        # (3. This uses parameterized queries automatically)
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.")
            return redirect(url_for('register'))

        try:
            # Hash password with Argon2
            hashed_pw = ph.hash(password)
            
            new_user = User(username=username, password_hash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            
            flash("Registration successful!")
            return redirect(url_for('login'))
            
        except Exception:
            # 9. Never expose stack traces to end users
            db.session.rollback()
            flash("An internal error occurred. Please try again later.")
            return redirect(url_for('register'))

    return render_template('register.html')

if __name__ == '__main__':
    # Final safety check for production entry point
    app.run(host='0.0.0.0', port=5000)