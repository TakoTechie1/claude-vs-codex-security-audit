import sqlite3
import os
import pickle
import subprocess
from flask import Flask, request, render_template_string, redirect, session, make_response
import hashlib

app = Flask(__name__)
app.secret_key = "super_secret_key_123"

DATABASE = "users.db"

def get_db():
      conn = sqlite3.connect(DATABASE)
      return conn

def init_db():
      conn = get_db()
      conn.execute("""
          CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY,
              username TEXT,
              password TEXT,
              email TEXT,
              role TEXT DEFAULT 'user'
          )
      """)
      conn.execute("""
          CREATE TABLE IF NOT EXISTS posts (
              id INTEGER PRIMARY KEY,
              user_id INTEGER,
              title TEXT,
              content TEXT,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
      """)
      conn.commit()
      conn.close()

# VULNERABILITY 1: SQL Injection in login
@app.route('/login', methods=['GET', 'POST'])
def login():
      if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']

        conn = get_db()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
                      session['user_id'] = user[0]
                      session['username'] = user[1]
                      session['role'] = user[4]
                      return redirect('/dashboard')
                  return "Invalid credentials"

    return render_template_string("""
            <form method="POST">
                        <input name="username" placeholder="Username">
                                    <input name="password" type="password" placeholder="Password">
                                                <button type="submit">Login</button>
                                                        </form>
                                                            """)

# VULNERABILITY 2: Stored XSS
@app.route('/post', methods=['GET', 'POST'])
def create_post():
      if request.method == 'POST':
                title = request.form['title']
                content = request.form['content']
                user_id = session.get('user_id', 1)

        conn = get_db()
        conn.execute(f"INSERT INTO posts (user_id, title, content) VALUES ({user_id}, '{title}', '{content}')")
        conn.commit()
        conn.close()
        return redirect('/posts')

    return render_template_string("""
            <form method="POST">
                        <input name="title" placeholder="Title">
                                    <textarea name="content" placeholder="Content"></textarea>
                                                <button type="submit">Create Post</button>
                                                        </form>
                                                            """)

# VULNERABILITY 3: XSS via render_template_string
@app.route('/posts')
def view_posts():
      conn = get_db()
    posts = conn.execute("SELECT * FROM posts ORDER BY created_at DESC").fetchall()
    conn.close()

    html = "<h1>All Posts</h1>"
    for post in posts:
              html += f"<h2>{post[2]}</h2><p>{post[3]}</p><hr>"

    return render_template_string(html)

# VULNERABILITY 4: Command Injection
@app.route('/ping')
def ping():
      host = request.args.get('host', '127.0.0.1')
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return f"<pre>{result.decode()}</pre>"

# VULNERABILITY 5: Path Traversal
@app.route('/download')
def download_file():
      filename = request.args.get('file', '')
    filepath = os.path.join('/uploads', filename)

    with open(filepath, 'r') as f:
              content = f.read()

    response = make_response(content)
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response

# VULNERABILITY 6: Insecure Deserialization
@app.route('/load_session')
def load_session():
      data = request.args.get('data', '')
      session_data = pickle.loads(bytes.fromhex(data))
      return f"Session loaded: {session_data}"

# VULNERABILITY 7: Weak Password Hashing (MD5)
@app.route('/register', methods=['GET', 'POST'])
def register():
      if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                email = request.form['email']

        password_hash = hashlib.md5(password.encode()).hexdigest()

        conn = get_db()
        conn.execute(f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password_hash}', '{email}')")
        conn.commit()
        conn.close()

        return redirect('/login')

    return render_template_string("""
            <form method="POST">
                        <input name="username" placeholder="Username">
                                    <input name="password" type="password" placeholder="Password">
                                                <input name="email" placeholder="Email">
                                                            <button type="submit">Register</button>
                                                                    </form>
                                                                        """)

# VULNERABILITY 8: IDOR - Insecure Direct Object Reference
@app.route('/user/<int:user_id>')
def get_user(user_id):
      conn = get_db()
    user = conn.execute(f"SELECT * FROM users WHERE id={user_id}").fetchone()
    conn.close()

    if user:
              return f"Username: {user[1]}, Email: {user[3]}, Role: {user[4]}"
          return "User not found"

# VULNERABILITY 9: Debug mode enabled + No CSRF protection
# VULNERABILITY 10: Hardcoded credentials
ADMIN_PASSWORD = "admin123"
API_KEY = "sk-proj-abc123def456ghi789"

@app.route('/admin')
def admin_panel():
      if session.get('role') != 'admin':
                return "Access denied", 403

      conn = get_db()
      users = conn.execute("SELECT * FROM users").fetchall()
      conn.close()

    html = "<h1>Admin Panel</h1><table>"
    for user in users:
              html += f"<tr><td>{user[1]}</td><td>{user[3]}</td><td>{user[4]}</td></tr>"
          html += "</table>"
    return render_template_string(html)

if __name__ == '__main__':
      init_db()
      app.run(debug=True, host='0.0.0.0', port=5000)
