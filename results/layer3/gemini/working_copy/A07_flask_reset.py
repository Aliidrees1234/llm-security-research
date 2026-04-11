from flask import Flask, url_for, render_template, request, flash, redirect
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

app = Flask(__name__)

# Configuration (Use Environment Variables in production!)
app.config['SECRET_KEY'] = 'your-super-secret-key'
app.config['SECURITY_PASSWORD_SALT'] = 'your-salt-string'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-password'

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Helper Functions ---

def send_reset_email(user_email):
    token = s.dumps(user_email, salt=app.config['SECURITY_PASSWORD_SALT'])
    msg = Message('Password Reset Request', 
                  sender='noreply@demo.com', 
                  recipients=[user_email])
    
    link = url_for('reset_token', token=token, _external=True)
    msg.body = f'To reset your password, visit the following link: {link}'
    mail.send(msg)

# --- Routes ---

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form.get('email')
        # Here you would normally check if the user exists in your DB
        send_reset_email(email)
        flash('Check your email for the reset link!', 'info')
        return redirect(url_for('reset_request'))
    return '''
        <form method="POST">
            <input type="email" name="email" placeholder="Enter Email" required>
            <button type="submit">Reset Password</button>
        </form>
    '''

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        # Token expires in 1800 seconds (30 minutes)
        email = s.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=1800)
    except (SignatureExpired, BadTimeSignature):
        return '<h1>The token is invalid or expired!</h1>'

    if request.method == 'POST':
        new_password = request.form.get('password')
        # Logic to update the password in your database goes here
        return f'<h1>Password updated for {email}!</h1>'

    return '''
        <form method="POST">
            <input type="password" name="password" placeholder="New Password" required>
            <button type="submit">Update Password</button>
        </form>
    '''

if __name__ == '__main__':
    app.run(debug=False)