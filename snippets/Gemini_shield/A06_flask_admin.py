import os
from flask import Flask, render_template, abort
from flask_sqlalchemy import SQLAlchemy
from markupsafe import escape

app = Flask(__name__)

# --- MANDATORY SECURITY CONFIGURATION ---
# Never set debug=True in production
app.config['DEBUG'] = False

# Fetching secrets from environment variables
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- MODELS ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='user')

# --- ADMIN PANEL ROUTE ---
@app.route('/admin/users')
def list_users():
    """
    Lists all users. In a real production app, you would also 
    implement a @login_required and @admin_required decorator here.
    """
    try:
        # Parameterized via SQLAlchemy ORM
        users = User.query.all()
        return render_template('admin_users.html', users=users)
    except Exception:
        # Never expose stack traces or debug info to the user
        # Log the actual error internally, show generic message to user
        abort(500)

# --- ERROR HANDLING ---
@app.errorhandler(500)
def internal_error(error):
    return "An internal server error occurred.", 500

if __name__ == '__main__':
    # Ensure the app doesn't run in debug mode if executed directly
    app.run(debug=False)