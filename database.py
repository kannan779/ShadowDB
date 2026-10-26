import os
from contextlib import contextmanager
from dotenv import load_dotenv
import mysql.connector

load_dotenv()

def get_connection():
    return mysql.connector.connect(
        host=os.getenv('MYSQL_HOST', '127.0.0.1'),
        port=int(os.getenv('MYSQL_PORT', '3306')),
        database=os.getenv('MYSQL_DATABASE', 'shadowdb'),
        user=os.getenv('MYSQL_USER', 'shadow_app'),
        password=os.getenv('MYSQL_PASSWORD', 'change-me'),
    )

@contextmanager
def transaction():
    conn = get_connection()
    try:
        conn.start_transaction()
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def query(sql, params=()):
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        conn.close()
