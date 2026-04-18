from flask import Flask, jsonify, abort
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Simple User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    bio = db.Column(db.Text)

@app.route('/profile/<int:user_id>', methods=['GET'])
def get_user_profile(user_id):
    # .get_or_404 is a lifesaver—it handles the "not found" logic for you
    user = User.query.get_or_404(user_id)
    
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "bio": user.bio
    }), 200

if __name__ == '__main__':
    app.run(debug=True)