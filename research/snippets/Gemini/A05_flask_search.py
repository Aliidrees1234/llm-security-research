from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

@app.route('/search')
def search():
    # Get the search query from the URL (e.g., /search?q=python)
    query = request.args.get('q')
    
    if query:
        # Filter posts where the title or content contains the query
        results = Post.query.filter(
            (Post.title.contains(query)) | (Post.content.contains(query))
        ).all()
    else:
        results = []

    return render_template('search_results.html', results=results, query=query)