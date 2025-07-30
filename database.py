
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

def get_alerts_by_filter(src_ip=None, dst_ip=None, attack_type=None, start_time=None, end_time=None):
    try:
        c = conn.cursor()
        query = "SELECT timestamp, src, dst, reason, hostname, attack_type FROM alerts WHERE 1=1"
        params = []

        if src_ip:
            query += " AND src = ?"
            params.append(src_ip)
        if dst_ip:
            query += " AND dst = ?"
            params.append(dst_ip)
        if attack_type:
            query += " AND attack_type = ?"
            params.append(attack_type)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += " ORDER BY timestamp DESC"
        c.execute(query, params)
        alerts = c.fetchall()
        return alerts
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
