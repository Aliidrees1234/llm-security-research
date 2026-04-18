from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Basic SQLite database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='User')

# Admin Route
@app.route('/admin/users')
def admin_users():
    # Fetch all users from the database
    all_users = User.query.all()
    return render_template('admin_users.html', users=all_users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Creates the database file
    app.run(debug=False)