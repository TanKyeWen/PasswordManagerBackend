import mysql
import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3306)),  # Default MySQL port
    'database': os.getenv('DB_NAME'), 
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD')
}

def get_db_connection():
    """Create and return a database connection"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def add_audit_entry(log_id, user_id, cred_id, activity_name, date, ip_address, timestamp):
    """Add an audit entry to the blockchain"""
    try:
        # Get database connection
        connection = get_db_connection()
        if not connection:
            return ({
                'success': False,
                'error': 'Service temporarily unavailable'
            }), 503

        try:
            cursor = connection.cursor(dictionary=True)

            # Insert new credential
            insert_query = """
                INSERT INTO audit_trail (log_id, user_id, cred_id, activity_name, date, ip_address, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """

            cursor.execute(insert_query, (
                log_id, user_id, cred_id, activity_name, date, ip_address, timestamp
            ))

            connection.commit()
            
        except Exception as db_error:
            return ({
                'success': False,
                'error': 'Failed to add credential'
            }), 500
            
        finally:
            if 'cursor' in locals():
                cursor.close()
            if connection:
                connection.close()
                
    except Exception as e:
        return ({
            'success': False,
            'error': 'Internal server error'
        }), 500

def seed_audit_trail(bcc):
    """Seed the database with initial data"""
    connection = get_db_connection()
    if connection is None:
        return
    cursor = connection.cursor()
    try:
        # Example of seeding data
        cursor.execute("SELECT * FROM audit_trail")

        result = cursor.fetchall()
        for row in result:
            bcc.add_audit_entry(
                log_id=row.log_id,
                user_id=row.user_id,
                cred_id=row.cred_id,
                activity_name=row.activity_name,
                ip_address=row.client_ip,
                date=row.date,
                timestamp=row.timestamp
            )

    except Error as e:
        print(f"Error seeding database: {e}")
    finally:
        cursor.close()
        connection.close()
