from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"  # swap for your DB URL
db = SQLAlchemy(app)


# --- Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    bio = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "bio": self.bio,
            "created_at": self.created_at.isoformat(),
        }


# --- Endpoint ---
@app.route("/users/<int:user_id>/profile", methods=["GET"])
def get_user_profile(user_id):
    user = db.session.get(User, user_id)

    if user is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"profile": user.to_dict()}), 200


# --- Init DB (dev only) ---
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)