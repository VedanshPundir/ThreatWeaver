import sqlite3
import os
import bcrypt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "websecsim.db")

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (username TEXT PRIMARY KEY, password_hash TEXT, role TEXT)''')
    conn.commit()

    c.execute("SELECT * FROM users WHERE username=?", ("admin",))
    if not c.fetchone():
        h = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        c.execute("INSERT INTO users VALUES (?, ?, ?)", ("admin", h, "admin"))
        print("Created admin/admin123")

    c.execute("SELECT * FROM users WHERE username=?", ("student",))
    if not c.fetchone():
        h = bcrypt.hashpw("student123".encode(), bcrypt.gensalt()).decode()
        c.execute("INSERT INTO users VALUES (?, ?, ?)", ("student", h, "student"))
        print("Created student/student123")

    conn.commit()
    conn.close()
    print(f"Database initialized at: {DB_NAME}")

def get_user(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    return user

def verify_password(plain_password, hashed_password):
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception as e:
        print(f"[DB] verify error: {e}")
        return False

if __name__ == "__main__":
    init_db()
