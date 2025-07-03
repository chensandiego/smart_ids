
import sqlite3
from datetime import datetime
from config import DB_NAME

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src TEXT,
            dst TEXT,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_alert(src, dst, reason):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO alerts (timestamp, src, dst, reason) VALUES (?, ?, ?, ?)", 
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), src, dst, reason))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def get_alerts():
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT timestamp, src, dst, reason FROM alerts ORDER BY timestamp DESC")
        alerts = c.fetchall()
        conn.close()
        return alerts
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
