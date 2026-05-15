import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(BASE_DIR, "url_guardian.db")

conn = sqlite3.connect(DATABASE_PATH)
cursor = conn.cursor()

cursor.execute("SELECT label, COUNT(*) FROM urls GROUP BY label")
rows = cursor.fetchall()

print("Label distribution:")
for row in rows:
    print(row)

conn.close()