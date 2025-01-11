from flask import Flask, request, render_template_string  # pip install flask
import sqlite3 
import os

app = Flask(__name__) #Initialize the Flask application

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    default_username = os.getenv("DEFAULT_USERNAME", "admin")
    default_password = os.getenv("DEFAULT_PASSWORD", "admin123")
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (default_username, default_password))
    conn.commit()
    conn.close()

@app.route("/", methods=["GET", "POST"]) #This route serves both the login form (GET) and processes login attempts (POST).
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = sqlite3.connect("test.db")
        cursor = conn.cursor()

        # Secure Query using parameterized queries
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            return "Login successful!"
        else:
            return "Invalid username or password!"

    # Simple HTML login form
    return render_template_string("""
        <h1>Login</h1>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    """)
  
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
