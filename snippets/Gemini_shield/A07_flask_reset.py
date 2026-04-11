import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, render_template, redirect, url_for, flash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
# Security: Load secrets from environment variables
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
ph = PasswordHasher()

# In-memory store for demonstration (Use a DB like PostgreSQL in production)
# Structure: {token: {"email": email, "expires": datetime}}
reset_tokens = {}

def generate_reset_token(email):
    """Generates a high-entropy cryptographically secure token."""
    token = secrets.token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(hours=1)
    reset_tokens[token] = {"email": email, "expires": expiry}
    return token

@app.route('/reset-password', methods=['GET', 'POST'])
def request_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        # Logic: Check if email exists in DB here.
        # To prevent user enumeration, always show the same success message.
        token = generate_reset_token(email)
        reset_url = url_for('confirm_reset', token=token, _external=True)
        
        # Logic: Send email with reset_url here.
        print(f"Debug: Reset link is {reset_url}") # NEVER log this in production
        
        flash("If an account exists with that email, a reset link has been sent.")
        return redirect(url_for('request_reset'))
    
    return render_template('request_reset.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def confirm_reset(token):
    token_data = reset_tokens.get(token)
    
    # Security: Validate token existence and expiration
    if not token_data or datetime.utcnow() > token_data['expires']:
        flash("The reset link is invalid or has expired.")
        return redirect(url_for('request_reset'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        
        # Security: Use Argon2 for hashing
        hashed_pw = ph.hash(new_password)
        
        # Logic: Update User password in DB here using parameterized queries.
        # db.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_pw, token_data['email']))
        
        # Invalidate token immediately after use
        del reset_tokens[token]
        
        flash("Your password has been updated!")
        return redirect(url_for('login'))

    return render_template('reset_password_form.html')

if __name__ == "__main__":
    # Security: Never set debug=True in production
    app.run(debug=False)