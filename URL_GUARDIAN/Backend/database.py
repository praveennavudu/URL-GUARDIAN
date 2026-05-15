import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(BASE_DIR, "url_guardian.db")

def create_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE,
        label TEXT,
        threat_type TEXT,
        source TEXT,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

    conn.commit()
    conn.close()
    print("Database ready.")

if __name__ == "__main__":
    create_database()
