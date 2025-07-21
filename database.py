
import sqlite3
from datetime import datetime
from config import DB_NAME

conn = None

def init_db():
    global conn
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src TEXT,
            dst TEXT,
            reason TEXT,
            hostname TEXT,
            attack_type TEXT
        )
    ''')
    c.execute('''
        ALTER TABLE alerts ADD COLUMN attack_type TEXT
    ''')
    conn.commit()

def insert_alert(src, dst, reason, hostname, attack_type=None):
    try:
        c = conn.cursor()
        c.execute("INSERT INTO alerts (timestamp, src, dst, reason, hostname, attack_type) VALUES (?, ?, ?, ?, ?, ?)", 
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), src, dst, reason, hostname, attack_type))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def get_alerts():
    try:
        c = conn.cursor()
        c.execute("SELECT timestamp, src, dst, reason, hostname, attack_type FROM alerts ORDER BY timestamp DESC")
        alerts = c.fetchall()
        return alerts
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
