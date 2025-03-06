from flask import Flask, render_template, request, redirect, url_for, flash, session
from cryptography.fernet import Fernet
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'wj46T_x6NDmqQWHnbGrgUDn1V-RC9RfT1rhUjjcnb_w=' 

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    else:
        generate_key()
        return load_key()

def encrypt_file(file_path):
    key = load_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    return encrypted_file_path

def decrypt_file(file_path):
    key = load_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    original_file_path = file_path.replace(".enc", "")
    with open(original_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    return original_file_path

@app.route('/')
def home():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose another.', 'danger')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'username' not in session:
        return redirect(url_for('login'))

    file = request.files['file']
    if file:
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)
        encrypted_file_path = encrypt_file(file_path)
        flash(f'File encrypted and saved as {encrypted_file_path}.', 'success')
    return redirect(url_for('home'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'username' not in session:
        return redirect(url_for('login'))

    file = request.files['file']
    if file:
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)
        decrypted_file_path = decrypt_file(file_path)
        flash(f'File decrypted and saved as {decrypted_file_path}.', 'success')
    return redirect(url_for('home'))

# Dynamically create templates
def create_templates():
    os.makedirs("templates", exist_ok=True)

    login_html = """<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    <form method="POST" action="/login">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br>
        <button type="submit">Login</button>
    </form>
    <p>Don't have an account? <a href="/register">Register here</a>.</p>
</body>
</html>"""

    register_html = """<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
</head>
<body>
    <h1>Register</h1>
    <form method="POST" action="/register">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br>
        <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="/login">Login here</a>.</p>
</body>
</html>"""

    dashboard_html = """<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <form method="POST" action="/encrypt" enctype="multipart/form-data">
        <h2>Encrypt a File</h2>
        <label for="file">Choose a file:</label>
        <input type="file" id="file" name="file" required>
        <button type="submit">Encrypt</button>
    </form>
    <form method="POST" action="/decrypt" enctype="multipart/form-data">
        <h2>Decrypt a File</h2>
        <label for="file">Choose a file:</label>
        <input type="file" id="file" name="file" required>
        <button type="submit">Decrypt</button>
    </form>
    <a href="/logout">Logout</a>
</body>
</html>"""

    with open("templates/login.html", "w") as file:
        file.write(login_html)

    with open("templates/register.html", "w") as file:
        file.write(register_html)

    with open("templates/dashboard.html", "w") as file:
        file.write(dashboard_html)

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    create_templates()
    init_db()
    app.run(debug=True)
