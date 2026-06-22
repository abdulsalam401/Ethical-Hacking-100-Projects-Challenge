#!/usr/bin/env python3
from flask import Flask, request, g
import sqlite3

app = Flask(__name__)
DATABASE = 'test_lab.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.before_request
def init_db():
    """Ensures database tables are verified and seeded cleanly."""
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute("DROP TABLE IF EXISTS artists")
    cursor.execute("CREATE TABLE IF NOT EXISTS artists (id INTEGER, name TEXT)")
    cursor.execute("INSERT INTO artists VALUES (1, 'Custom Local Lab Artist')")
    db.commit()
    db.close()

@app.route('/artists.php')
def artists():
    artist_id = request.args.get('artist', '')
    db = get_db()
    cursor = db.cursor()
    
    # INTENTIONAL INJECTION VECTOR: Unsanitized concatenation
    query = f"SELECT * FROM artists WHERE id = '{artist_id}'"
    
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        if result:
            return f"<html><body><h1>Artist Profiles</h1><p>{result[0][1]}</p></body></html>"
        else:
            return "<html><body><h1>Artist Profiles</h1></body></html>"
    except Exception as e:
        return "Database Error encountered.", 500

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)