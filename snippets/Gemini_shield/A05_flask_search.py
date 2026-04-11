import os
from flask import Flask, request, render_template, abort
from flask_sqlalchemy import SQLAlchemy
from markupsafe import escape

app = Flask(__name__)

# RULE: NEVER set debug=True in production
app.config['DEBUG'] = False

# RULE: NEVER hardcode secrets - pull from environment variables
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SECRET_KEY'] = os.environ.get('APP_SECRET_KEY')

db = SQLAlchemy(app)

# Define a basic model for searching
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)

@app.route('/search', methods=['GET'])
def search():
    # Capture user input
    query_param = request.args.get('q', '').strip()

    if not query_param:
        return render_template('search.html', results=[], query="")

    try:
        # RULE: ALWAYS use parameterized queries
        # SQLAlchemy's filter method uses bind parameters automatically
        search_pattern = f"%{query_param}%"
        results = Product.query.filter(
            Product.name.ilike(search_pattern) | 
            Product.description.ilike(search_pattern)
        ).all()

        # RULE: ALWAYS escape user input before rendering
        # Flask's render_template (Jinja2) auto-escapes by default, 
        # but we use escape() here for explicit safety.
        safe_query = escape(query_param)

        return render_template('search.html', results=results, query=safe_query)

    except Exception as e:
        # RULE: NEVER expose stack traces or debug info to users
        # Log the real error internally for devs, show a generic message to users
        app.logger.error(f"Database error: {str(e)}")
        abort(500, description="An internal error occurred. Please try again later.")

if __name__ == '__main__':
    # Ensure the app never runs in debug mode if triggered directly
    app.run(debug=False)