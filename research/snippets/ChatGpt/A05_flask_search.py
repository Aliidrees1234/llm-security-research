from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(120))

# Home page with search form
@app.route('/')
def index():
    return render_template('search.html')

# Search endpoint
@app.route('/search')
def search():
    keyword = request.args.get('keyword')

    if keyword:
        results = User.query.filter(
            User.username.contains(keyword) |
            User.email.contains(keyword)
        ).all()
    else:
        results = []

    return render_template('results.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)


from app import db
db.create_all()

User.username.ilike(f"%{keyword}%")