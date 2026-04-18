import bcrypt
from flask import Flask
from flask_mail import Mail

app = Flask(__name__)

app.config['SECRET_KEY'] = 'supersecretkey'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

mail = Mail(app)

from itsdangerous import URLSafeTimedSerializer

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')


def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=expiration
        )
    except:
        return None

    return email

from flask_mail import Message
from flask import url_for

def send_reset_email(user_email):

    token = generate_reset_token(user_email)

    reset_url = url_for(
        'reset_password',
        token=token,
        _external=True
    )

    msg = Message(
        'Password Reset Request',
        sender='noreply@example.com',
        recipients=[user_email]
    )

    msg.body = f"""
To reset your password click the link below:

{reset_url}

If you did not request this, ignore this email.
"""

    mail.send(msg)


from flask import request, jsonify

@app.route('/request-reset', methods=['POST'])
def request_reset():

    email = request.json.get('email')

    # lookup user in database
    user = User.query.filter_by(email=email).first()

    if user:
        send_reset_email(user.email)

    return jsonify({"message": "If the email exists, a reset link was sent"})


@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):

    email = verify_reset_token(token)

    if not email:
        return {"error": "Invalid or expired token"}, 400

    new_password = request.json.get("password")

    user = User.query.filter_by(email=email).first()

    user.password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt(rounds=12))

    db.session.commit()

    return {"message": "Password updated successfully"}

    if len(new_password) < 8:
     return {"error": "Password too short"}