from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///comments.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Comment Model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)

# Home page (show comments)
@app.route("/")
def index():
    comments = Comment.query.order_by(Comment.id.desc()).all()
    return render_template("index.html", comments=comments)

# Add comment
@app.route("/add_comment", methods=["POST"])
def add_comment():
    username = request.form["username"]
    content = request.form["content"]

    new_comment = Comment(username=username, content=content)
    db.session.add(new_comment)
    db.session.commit()

    return redirect("/")

# Run server
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)

from markupsafe import escape