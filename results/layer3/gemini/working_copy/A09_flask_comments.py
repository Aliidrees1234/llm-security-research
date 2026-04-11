from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

# Configure SQLite Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///comments.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the Comment Model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

# Create the database within the application context
with app.app_context():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user = request.form.get('username')
        text = request.form.get('content')
        
        if user and text:
            new_comment = Comment(username=user, content=text)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('index'))

    # Fetch all comments, newest first
    comments = Comment.query.order_by(Comment.date_posted.desc()).all()
    return render_template('index.html', comments=comments)

if __name__ == '__main__':
    app.run(debug=False)