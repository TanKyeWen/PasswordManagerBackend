from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
import os
from datetime import datetime
import encryption_module  # Encryption and decryption functions for credentials
import logging
import jwt
import re # For email validation
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
website_url = os.getenv('WEBSITE_URL')

app = Flask(__name__)
AES_secret_key = os.getenv('AES_SECRET_KEY')

# Configure CORS for your entire app or specific routes
CORS(app, 
     origins=[website_url], 
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

# Database configuration
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

def init_database():
    """Initialize the database and create tables"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            
            # Quick drop for development/testing
            cursor.execute("DROP TABLE IF EXISTS credentials, users, encryption_keys")
            connection.commit()
            logger.info("Dropped existing tables if they existed")

            # Create users table
            create_users_table = """
            CREATE TABLE IF NOT EXISTS users (
                uid INT AUTO_INCREMENT PRIMARY KEY,
                uName VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
                last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
            """
            logger.info("Create Users table SQL: %s", create_users_table)

            # Create credentials table
            create_credentials_table = """
            CREATE TABLE IF NOT EXISTS credentials (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                credential_website VARCHAR(100) NOT NULL,
                credential_username VARCHAR(100) NOT NULL,
                credential_password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                created_ip_address VARCHAR(50) NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(uid) ON DELETE CASCADE
            )
            """
            logger.info("Create Credentials table SQL: %s", create_credentials_table)

            # Create Encryption key table
            create_encryption_key_table = """
            CREATE TABLE IF NOT EXISTS encryption_keys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                c_id INT NOT NULL,
                encryption_key VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(uid) ON DELETE CASCADE
                FOREIGN KEY (c_id) REFERENCES credentials(id) ON DELETE CASCADE
            )
            """
            logger.info("Create Encryption Keys table SQL: %s", create_encryption_key_table)

            # Execute separately
            cursor.execute(create_users_table)
            cursor.execute(create_credentials_table)
            connection.commit()
            print("Database initialized successfully")
            
        except Error as e:
            print(f"Error creating table: {e}")
        finally:
            cursor.close()
            connection.close()

@app.before_request
def add_security_headers(response):
    """Add security headers to response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # More restrictive CSP for better security
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;"
    response.headers['Content-Security-Policy'] = csp
    
    return response

def validate_jwt_token(token):
    """Validate JWT token and return user_id if valid"""
    try:
        # Replace with your JWT secret
        payload = jwt.decode(token, os.getenv('JWT_SECRET_TOKEN'), algorithms=['HS256'])
        return payload.get('user_id')
    except jwt.InvalidTokenError:
        return None

@app.route('/api/auth/signin', methods=['POST'])
def api_signin():
    """API endpoint for Vue.js authentication"""
    
    # Enable CORS for Vue.js
    response_headers = {
        'Access-Control-Allow-Origin': website_url,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Content-Type': 'application/json'
    }
    
    try:
        data = request.get_json()
        
        # Validate JSON data
        if not data:
            response = jsonify({'error': 'Invalid JSON data'})
            
            return response, 400
        
        # Retrieve username and password from JSON
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        # Check if username and password are provided
        if not username or not password:
            response = jsonify({'error': 'Username and password are required'})
            
            return response, 400
        
        # Authentication Logic
        connection = get_db_connection()
        if not connection:
            response = jsonify({'error': 'Database connection failed'})
            
            return response, 503
        
        try:
            cursor = connection.cursor(dictionary=True)

            # Query to find user by username or email and limit to one result 
            query = """
                SELECT uid, uName, email, password
                FROM users
                WHERE (email = %s OR uName = %s)
                LIMIT 1
            """
            cursor.execute(query, (username, username))
            user = cursor.fetchone()
            
            # Check if user exists and verify password
            if not user:
                logger.warning(f"Failed login attempt for non-existent user: {username}")
                response = jsonify({
                    'success': False,
                    'error': 'User not found'
                })
                
                return response, 404
            
            elif not encryption_module.verify_password(password, user['password']):
                logger.warning(f"Failed login attempt for user {user['uid']} ({user['uName']})")
                # Log failed login attempt
                response = jsonify({
                    'success': False,
                    'error': 'Invalid credentials'
                })
                
                return response, 401
            
            else:
                # Successful authentication
                # Update last_login
                logger.info(f"User {user['uid']} ({user['uName']}) logged in successfully on {datetime.now()}")
                query = """
                    UPDATE users
                    SET last_login = %s
                    WHERE uid = %s
                """
                cursor.execute(query, (datetime.now(), user['uid']))
                connection.commit()
                
                # Check if any rows were affected
                if cursor.rowcount == 0:
                    return jsonify({'error': 'Credential not found or no changes made'}), 404
            
                # Store user information in session
                session['user_id'] = user['uid']
                session['username'] = user['uName']
                
                response = jsonify({
                    'success': True,
                    'message': 'Authentication successful',
                    'user': {
                        'user_id': user['uid'],
                        'username': user['uName'],
                        'email': user['email']
                    }
                })
                
                return response, 200
                
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        response = jsonify({'error': 'Authentication failed'})
        
        return response, 500

@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    """API endpoint for user registration"""
    try:
        data = request.get_json()
        
        if not data:
            response = jsonify({'error': 'Invalid JSON data'})
            return response, 400
            
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        re_password = data.get('re-password', '')
        
        # Validate input
        if not username or not email or not password or not re_password:
            response = jsonify({'error': 'Username, email, and password are required'})
            return response, 400
        
        # Validate if password === re_password format
        if password != re_password:
            response = jsonify({'error': 'Passwords do not match'})
            return response, 400
        
        # Validate email format
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            response = jsonify({'error': 'Invalid email format'})
            return response, 400
        
        # Check if username or email already exists
        connection = get_db_connection()
        if not connection:
            response = jsonify({'error': 'Database connection failed'})
            return response, 503
        
        try:
            cursor = connection.cursor()
            
            # Check for existing username
            uName_query = """
                SELECT uid 
                FROM users 
                WHERE uName = %s
            """
            cursor.execute(uName_query, (username,))
            if cursor.fetchone():
                response = jsonify({'error': 'Username already exists'})
                return response, 409
            
            # Check for existing email
            email_query = """
                SELECT uid 
                FROM users 
                WHERE email = %s
            """
            cursor.execute(email_query, (email,))
            if cursor.fetchone():
                response = jsonify({'error': 'Email already exists'})
                return response, 409
            
            # Hash the password
            hashed_password = encryption_module.hash_password(password)
            insert_query = """
                INSERT INTO users (uName, email, password, created_at)
                VALUES (%s, %s, %s, %s)
            """
            
            cursor.execute(insert_query, (username, email, hashed_password, datetime.now()))
            connection.commit()
            
            user_id = cursor.lastrowid
            
            session['user_id'] = user_id
            session['username'] = username
            
            response = jsonify({
                'success': True,
                'message': 'User registered successfully',
                'user': {
                    'id': user_id,
                    'username': username,
                    'email': email
                }
            })
            return response, 201
            
        except Error as e:
            logger.error(f"Error during signup: {e}")
            response = jsonify({'error': str(e)})
            return response, 500
    
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
                
    except Exception as e:
        logger.error(f"Signup error: {e}")
        response = jsonify({'error': 'Signup failed'})
        return response, 500

@app.route('/api/vault', methods=['GET', 'OPTIONS'])
def get_vault_credentials():
    """Get all credentials for the authenticated user"""
    
    # Handle preflight OPTIONS request
    # if request.method == 'OPTIONS':
    #     response = jsonify({'status': 'ok'})
    #     response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
    #     response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With')
    #     response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    #     response.headers.add('Access-Control-Allow-Credentials', 'true')
    #     return response, 200
    
    try:
        # For GET requests, check query parameters instead of JSON body
        user_id_param = request.args.get('user_id')  # Optional: from query params
        
        # Check authentication from session (primary method)
        user_id = session.get('user_id')
        if not user_id:
            # Check Authorization header as fallback
            # auth_header = request.headers.get('Authorization')
            # if auth_header and auth_header.startswith('Bearer '):
            #     token = auth_header.split(' ')[1]
            #     user_id = validate_jwt_token(token)  # You'll need to implement this
            
            if not user_id:
                logger.warning(f"Unauthorized vault access attempt from IP: {request.remote_addr}")
                response = jsonify({
                    'success': False,
                    'error': 'Authentication required'
                })
                # Add CORS headers to error responses
                
                return response, 401
        
        # Validate user_id
        if not isinstance(user_id, (int, str)) or str(user_id).strip() == '':
            logger.error(f"Invalid user_id in session: {user_id}")
            response = jsonify({
                'success': False,
                'error': 'Invalid session data'
            })
            
            return response, 400
        
        # Optional: Verify user_id matches query parameter if provided
        if user_id_param and str(user_id) != str(user_id_param):
            logger.warning(f"User {user_id} attempted to access vault for user {user_id_param}")
            response = jsonify({
                'success': False,
                'error': 'Unauthorized access to another user\'s vault'
            })
            
            return response, 403
        
        connection = get_db_connection()
        if not connection:
            logger.error("Database connection failed for vault access")
            response = jsonify({
                'success': False,
                'error': 'Service temporarily unavailable'
            })
            
            return response, 503
        
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Select only necessary fields for vault page
            query = """
                SELECT
                    id,
                    credential_website,
                    credential_username,
                    created_at,
                    updated_at
                FROM credentials
                WHERE user_id = %s
                ORDER BY credential_website ASC
            """
            
            cursor.execute(query, (user_id,))
            credentials = cursor.fetchall()
            
            # Log successful access
            logger.info(f"User {user_id} accessed vault - {len(credentials)} credentials retrieved")
            
            # Convert datetime objects to strings for JSON serialization
            for credential in credentials:
                if credential.get('created_at'):
                    credential['created_at'] = credential['created_at'].isoformat()
                if credential.get('updated_at'):
                    credential['updated_at'] = credential['updated_at'].isoformat()
            
            response = jsonify({
                'success': True,
                'message': f'Retrieved {len(credentials)} credentials',
                'data': credentials,  # Changed: return array directly, not nested object
                'total_count': len(credentials),
                'user_id': user_id
            })
            
            # Add security headers
            add_security_headers(response)
            
            
            return response, 200
            
        except Exception as e:
            logger.error(f"Database error while fetching credentials for user {user_id}: {e}")
            response = jsonify({
                'success': False,
                'error': 'Failed to retrieve credentials'
            })
            
            return response, 500
            
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    except Exception as e:
        logger.error(f"Unexpected error in vault access: {e}")
        response = jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        })
        
        return response, 500

# Additional endpoint for sync functionality
@app.route('/api/vault/sync', methods=['GET'])
def get_vault_sync():
    """Get vault data for sync (with since parameter)"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            response = jsonify({'success': False, 'error': 'Authentication required'})
            
            return response, 401
        
        # Get 'since' parameter for incremental sync
        since = request.args.get('since', '1970-01-01T00:00:00Z')
        
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = """
            SELECT
                id,
                credential_website,
                credential_username,
                created_at,
                updated_at
            FROM credentials
            WHERE user_id = %s AND created_at >= %s
        """
        
        cursor.execute(query, (user_id, since))
        credentials = cursor.fetchall()
        
        # Convert datetime to ISO format
        for credential in credentials:
            if credential.get('created_at'):
                credential['created_at'] = credential['created_at'].isoformat()
            if credential.get('updated_at'):
                credential['updated_at'] = credential['updated_at'].isoformat()
        
        response = jsonify(credentials)
        add_security_headers(response)
        
        
        return response, 200
        
    except Exception as e:
        logger.error(f"Vault sync error: {e}")
        response = jsonify({'success': False, 'error': 'Sync failed'})
        
        return response, 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

# Move to SQLite
@app.route('/api/credential/<int: id>', methods=['GET'])
def get_individual_credential(c_id):
    """Get one credentials for the authenticated user"""
    try:
        data = request.get_json()
        
        # Validate JSON data
        if not data:
            response = jsonify({'error': 'Invalid JSON data'})
            return response, 400

        # Check authentication
        user_id = session.get('user_id')
        if not user_id:
            logger.warning(f"Unauthorized vault access attempt from IP: {request.remote_addr}")
            response = jsonify({
                'success': False,
                'error': 'Authentication required'
            })
            return response, 401
        
        # Validate user_id
        if not isinstance(user_id, (int, str)) or str(user_id).strip() == '':
            logger.error(f"Invalid user_id in session: {user_id}")
            response = jsonify({
                'success': False,
                'error': 'Invalid session data'
            })
            return response, 400
        
        connection = get_db_connection()
        if not connection:
            logger.error("Database connection failed for vault access")
            response = jsonify({
                'success': False,
                'error': 'Service temporarily unavailable'
            })
            return response, 503
        
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Validate owner of the credential
            validate_query = """
                SELECT user_id
                FROM credentials 
                WHERE id = %s
            """
            cursor.execute(validate_query, (c_id,))
            owner = cursor.fetchone()

            if not owner or owner['user_id'] != user_id:
                logger.warning(f"Unauthorized access attempt to credential {c_id} by user {user_id}")
                response = jsonify({
                    'success': False,
                    'error': 'Unauthorized access to credential'
                })
                return response, 403

            # Select only necessary fields for credential
            query = """
                SELECT 
                    credential_website,
                    credential_username,
                    credential_password,
                FROM credentials 
                WHERE id = %s and user_id = %s
            """
            
            cursor.execute(query, (user_id, c_id))
            credential = cursor.fetchone()
            
            # Log successful access
            logger.info(f"User {user_id} accessed vault - {c_id} credential retrieved")
            
            # Optional: Remove sensitive data for certain use cases
            # Or add encryption/decryption here if needed
            
            response = jsonify({
                'success': True,
                'message': f'Retrieved {c_id} credential',
                'data': {
                    'credentials': credential,
                    'user_id': user_id
                }
            })
            return response, 200
            
        except Error as e:
            logger.error(f"Database error while fetching credentials for user {user_id}: {e}")
            response = jsonify({
                'success': False,
                'error': 'Failed to retrieve credentials'
            })
            return response, 500
            
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    except Exception as e:
        logger.error(f"Unexpected error in credential access: {e}")
        response = jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        })
        return response, 500

# Move to SQLite
@app.route('/api/credential/<int: id>', methods=['PATCH'])
def update_credential(c_id):
    """Update credentials for the authenticated user"""
    try:
        data = request.get_json()
        
        # Validate JSON data
        if not data:
            response = jsonify({'error': 'Invalid JSON data'})
            return response, 400

        # Check authentication
        user_id = session.get('user_id')
        if not user_id:
            logger.warning(f"Unauthorized vault access attempt from IP: {request.remote_addr}")
            response = jsonify({
                'success': False,
                'error': 'Authentication required'
            })
            return response, 401
        
        # Validate user_id
        if not isinstance(user_id, (int, str)) or str(user_id).strip() == '':
            logger.error(f"Invalid user_id in session: {user_id}")
            response = jsonify({
                'success': False,
                'error': 'Invalid session data'
            })
            return response, 400
        
        connection = get_db_connection()
        if not connection:
            logger.error("Database connection failed for vault access")
            response = jsonify({
                'success': False,
                'error': 'Service temporarily unavailable'
            })
            return response, 503
        
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Validate owner of the credential
            validate_query = """
                SELECT user_id
                FROM credentials 
                WHERE id = %s
            """
            cursor.execute(validate_query, (c_id,))
            owner = cursor.fetchone()
            
            if not owner or owner['user_id'] != user_id:
                logger.warning(f"Unauthorized access attempt to credential {c_id} by user {user_id}")
                response = jsonify({
                    'success': False,
                    'error': 'Unauthorized access to credential'
                })
                return response, 403
            
            # Validate input data
            if not data.get('credential_website') or not data.get('credential_username') or not data.get('credential_password'):
                response = jsonify({'error': 'Website, username, and password are required'})
                return response, 400
            
            # Update credential
            update_query = """
                UPDATE credentials
                SET credential_website = %s,
                    credential_username = %s,
                    credential_password = %s,
                    updated_at = %s
                WHERE id = %s AND user_id = %s
            """
            
            cursor.execute(update_query, (
                user_id, data.get('credential_website', ''),
                data.get('credential_username', ''),
                data.get('credential_password', ''), 
                datetime.now(), 
                c_id, 
                user_id))
            connection.commit()
            
            # Check if any rows were affected
            if cursor.rowcount == 0:
                return jsonify({'error': 'Credential not found or no changes made'}), 404

            # Log successful update
            logger.info(f"User {user_id} updated credential - {c_id}")
            
            # Optional: Remove sensitive data for certain use cases
            # Or add encryption/decryption here if needed
            
            response = jsonify({
                'success': True,
                'message': f'Updated credential: {c_id}',
                'data': {
                    'updated_credential': c_id,
                    'user_id': user_id
                }
            })
            return response, 200
            
        except Error as e:
            logger.error(f"Database error while fetching credentials for user {user_id}: {e}")
            response = jsonify({
                'success': False,
                'error': 'Failed to retrieve credentials'
            })
            return response, 500
            
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    except Exception as e:
        logger.error(f"Unexpected error in credential access: {e}")
        response = jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        })
        return response, 500

# Move to SQLite
@app.route('/api/credential', methods=['POST'])
def add_credential(c_id):
    """Add credentials for the authenticated user"""
    try:
        data = request.get_json()
        
        # Validate JSON data
        if not data:
            response = jsonify({'error': 'Invalid JSON data'})
            return response, 400

        # Check authentication
        user_id = session.get('user_id')
        if not user_id:
            logger.warning(f"Unauthorized vault access attempt from IP: {request.remote_addr}")
            response = jsonify({
                'success': False,
                'error': 'Authentication required'
            })
            return response, 401
        
        # Validate user_id
        if not isinstance(user_id, (int, str)) or str(user_id).strip() == '':
            logger.error(f"Invalid user_id in session: {user_id}")
            response = jsonify({
                'success': False,
                'error': 'Invalid session data'
            })
            return response, 400
        
        connection = get_db_connection()
        if not connection:
            logger.error("Database connection failed for vault access")
            response = jsonify({
                'success': False,
                'error': 'Service temporarily unavailable'
            })
            return response, 503
        
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Validate owner of the credential
            validate_query = """
                SELECT user_id
                FROM credentials 
                WHERE id = %s
            """
            cursor.execute(validate_query, (c_id,))
            owner = cursor.fetchone()
            
            if not owner or owner['user_id'] != user_id:
                logger.warning(f"Unauthorized access attempt to credential {c_id} by user {user_id}")
                response = jsonify({
                    'success': False,
                    'error': 'Unauthorized access to credential'
                })
                return response, 403
            
            # Validate input data
            if not data.get('credential_website') or not data.get('credential_username') or not data.get('credential_password'):
                response = jsonify({'error': 'Website, username, and password are required'})
                return response, 400
            
            # Update credential
            add_query = """
                INSERT INTO credentials (user_id, credential_website, credential_username, credential_password, created_at, created_ip_address)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(add_query, (
                user_id, 
                data.get('credential_website', ''),
                data.get('credential_username', ''),
                data.get('credential_password', ''), 
                datetime.now(), 
                c_id, 
                user_id))
            connection.commit()
            
            # Check if any rows were affected
            if cursor.rowcount == 0:
                return jsonify({'error': 'Credential not found or no changes made'}), 404

            # Log successful update
            logger.info(f"User {user_id} updated credential - {c_id}")
            
            # Optional: Remove sensitive data for certain use cases
            # Or add encryption/decryption here if needed
            
            response = jsonify({
                'success': True,
                'message': f'Updated credential: {c_id}',
                'data': {
                    'updated_credential': c_id,
                    'user_id': user_id
                }
            })
            
            return response, 200
            
        except Error as e:
            logger.error(f"Database error while fetching credentials for user {user_id}: {e}")
            response = jsonify({
                'success': False,
                'error': 'Failed to retrieve credentials'
            })
            
            return response, 500
            
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    except Exception as e:
        logger.error(f"Unexpected error in credential access: {e}")
        response = jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        })
        
        return response, 500

@app.route('/api/generate-password', methods=['GET'])
def generate_password():
    """Generate a random password"""
    return 0

if __name__ == '__main__':
    # Initialize database on startup
    init_database()
    app.run(host='0.0.0.0', port=9011, debug=True)