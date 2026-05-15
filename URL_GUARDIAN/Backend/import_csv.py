import sqlite3
import pandas as pd
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(BASE_DIR, "url_guardian.db")

RAW_DATA_PATH = os.path.join(BASE_DIR, "Raw data")


def import_csv(file_name, threat_type):

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    file_path = os.path.join(RAW_DATA_PATH, file_name)

    df = pd.read_csv(file_path, on_bad_lines="skip")

    for url in df.iloc[:, 0]:
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO urls (url, threat_type) VALUES (?, ?)",
                (str(url), threat_type)
            )
        except:
            continue

    conn.commit()
    conn.close()

    print(f"Imported {file_name} as {threat_type}")


if __name__ == "__main__":

    import_csv("safe Url_file.csv", "legit")
    import_csv("malicious(unsafe).csv", "malware")