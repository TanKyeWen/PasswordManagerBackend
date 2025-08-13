import ipaddress
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_cors import CORS
from functools import wraps
import mysql.connector
from mysql.connector import Error
import os
from datetime import datetime, timedelta
import encryption_module as enc # Encryption and decryption functions for credentials
import password_generation_module as pg # Password generation functions
import password_health_module as ph # Password health funtions
import blockchain_communication_module as bcc
import logging
from web3 import Web3
import jwt
import re # For email validation
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

# Configure logging
# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
website_url = os.getenv('WEBSITE_URL')

# BlockChain Setup
BESU_URL = os.getenv('BESU_URL')
CHAIN_ID = int(os.getenv('CHAIN_ID'))
w3 = Web3(Web3.HTTPProvider(BESU_URL))
account_address = None
private_key = None
contract = None

# CORS and Flask Setup
app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET_KEY')
app.config['SECRET_KEY'] = os.getenv('SESSION_SECRET_KEY')
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_DOMAIN'] = None  # Let Flask handle this automatically
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # Adjust as needed
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True
)

# AES Setup
AES_secret_key = bytes.fromhex(os.getenv('AES_SECRET_KEY'))

# Configure CORS for your entire app or specific routes
CORS(app,
     origins=[website_url],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     expose_headers=['Set-Cookie'],
     max_age=3600)

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

def get_client_ip(request):
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        ip = forwarded_for.split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip

def require_auth(f, check_resource_owner=True):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip authentication for OPTIONS requests (CORS preflight)
        if request.method == 'OPTIONS':
            return f(*args, **kwargs)
           
        try:
            user_id = session.get('user_id')
           
            if not user_id:
                logger.warning(f"Unauthorized access attempt to {request.endpoint} from IP: {get_client_ip(request)}")
                return jsonify({
                    'success': False,
                    'error': 'Authentication required'
                }), 401
           
            # Convert to string and validate format (assuming string IDs)
            user_id = str(user_id).strip()
            if not user_id:
                logger.error("Invalid user_id format in session")
                return jsonify({
                    'success': False,
                    'error': 'Invalid session data'
                }), 400
           
            # Resource ownership validation
            if check_resource_owner:
                request_user_id = None
               
                # Check URL parameters
                if 'user_id' in kwargs:
                    request_user_id = str(kwargs['user_id']).strip()
               
                # Check JSON body
                elif request.is_json and request.json and 'user_id' in request.json:
                    request_user_id = str(request.json['user_id']).strip()
               
                # Check query parameters
                elif request.args.get('user_id'):
                    request_user_id = str(request.args.get('user_id')).strip()
               
                # Validate ownership with consistent string comparison
                if request_user_id and request_user_id != user_id:
                    logger.warning(
                        f"Access denied: User {user_id} attempted to access "
                        f"resources for user {request_user_id} from IP: {get_client_ip(request)}"
                    )
                    return jsonify({
                        'success': False,
                        'error': 'Access denied'
                    }), 403
           
            # Add user_id to request context
            request.current_user_id = user_id
            return f(*args, **kwargs)
           
        except Exception as e:
            logger.error(f"Authentication error in {request.endpoint}: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Authentication error'
            }), 500
   
    return decorated_function

def validate_request_data(required_fields=None, validation_rules=None):
    """
    Universal validation decorator for Flask API calls
    
    Args:
        required_fields (list): List of required field names
        validation_rules (dict): Dictionary of field_name: validation_function pairs
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if request contains JSON data
            if not request.is_json:
                return jsonify({
                    'success': False,
                    'error': 'Request must contain JSON data',
                    'code': 'INVALID_REQUEST_FORMAT'
                }), 400
            
            try:
                data = request.get_json()
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': 'Invalid JSON format',
                    'code': 'INVALID_JSON',
                    'details': str(e)
                }), 400
            
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'Empty request body',
                    'code': 'EMPTY_REQUEST'
                }), 400
            
            # Check required fields
            if required_fields:
                missing_fields = [field for field in required_fields if field not in data or not data[field]]
                if missing_fields:
                    return jsonify({
                        'success': False,
                        'error': f'Missing required fields: {", ".join(missing_fields)}',
                        'code': 'MISSING_FIELDS',
                        'missing_fields': missing_fields
                    }), 400
            
            # Apply validation rules
            if validation_rules:
                for field_name, validation_func in validation_rules.items():
                    if field_name in data:
                        try:
                            is_valid, error_message = validation_func(data[field_name])
                            if not is_valid:
                                return jsonify({
                                    'success': False,
                                    'error': f'Validation failed for field "{field_name}": {error_message}',
                                    'code': 'VALIDATION_ERROR',
                                    'field': field_name
                                }), 400
                        except Exception as e:
                            return jsonify({
                                'success': False,
                                'error': f'Validation error for field "{field_name}": {str(e)}',
                                'code': 'VALIDATION_EXCEPTION',
                                'field': field_name
                            }), 500
            
            # Add validated data to kwargs
            kwargs['validated_data'] = data
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Validation helper functions
def validate_user_id(user_id):
    """Validate user ID format"""
    if not isinstance(user_id, str):
        return False, "User ID must be a string"
    if len(user_id.strip()) == 0:
        return False, "User ID cannot be empty"
    if len(user_id) > 100:
        return False, "User ID too long (max 100 characters)"
    return True, None

def validate_cred_id(cred_id):
    """Validate credential ID format"""
    if not isinstance(cred_id, str):
        return False, "Credential ID must be a string"
    if len(cred_id.strip()) == 0:
        return False, "Credential ID cannot be empty"
    if len(cred_id) > 100:
        return False, "Credential ID too long (max 100 characters)"
    return True, None

def validate_activity_name(activity_name):
    """Validate activity name"""
    if not isinstance(activity_name, str):
        return False, "Activity name must be a string"
    if len(activity_name.strip()) == 0:
        return False, "Activity name cannot be empty"
    if len(activity_name) > 200:
        return False, "Activity name too long (max 200 characters)"
    return True, None

def validate_date(date_str):
    """Validate date format"""
    if not isinstance(date_str, str):
        return False, "Date must be a string"
    
    # Try multiple date formats
    date_formats = [
        '%Y-%m-%d',
        '%Y-%m-%d %H:%M:%S',
        '%d/%m/%Y',
        '%m/%d/%Y',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%SZ'
    ]
    
    for fmt in date_formats:
        try:
            datetime.strptime(date_str, fmt)
            return True, None
        except ValueError:
            continue
    
    return False, "Invalid date format. Use formats like YYYY-MM-DD or YYYY-MM-DD HH:MM:SS"

def validate_ip(ip_str):
    """Validate IP address format"""
    if not isinstance(ip_str, str):
        return False, "IP address must be a string"
    
    try:
        ipaddress.ip_address(ip_str)
        return True, None
    except ValueError:
        return False, "Invalid IP address format"

# Load Blockchain account and contract
def initialize_app_components():
    """Initialize account and contract, storing them globally for this file"""
    global account_address, private_key, contract
    
    try:
        # Load account using return values from bcc
        account_address, private_key = bcc.load_account()
        if not account_address:
            logger.error("Failed to load account")
            return False
        
        # Load contract using return values from bcc
        contract = bcc.load_contract()
        if not contract:
            logger.error("Failed to load contract")
            return False
        
        logger.info(f"App components initialized - Account: {account_address}")
        return True
        
    except Exception as e:
        logger.error(f"Error initializing app components: {e}")
        return False

@app.route('/api/user/session', methods=['GET', 'OPTIONS'])
@require_auth
def get_session():
    """Get current session information"""
    
    # Handle OPTIONS request for CORS
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        user_id = request.current_user_id
        username = session.get('username')
        
        return jsonify({
            'success': True,
            'data': {
                'user_id': user_id,
                'username': username
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error in session endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve session data'
        }), 500

@app.route('/api/auth/signin', methods=['POST'])
def api_signin():
    """API endpoint for Vue.js authentication"""
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
                
                return response, 401
            
            elif not enc.verify_password(password, user['password']):
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
        re_password = data.get('re_password', '')
        
        # Check for empty fields first
        if not username:
            response = jsonify({'error': 'Username is required'})
            return response, 400

        if not email:
            response = jsonify({'error': 'Email is required'})
            return response, 400

        if not password:
            response = jsonify({'error': 'Password is required'})
            return response, 400

        if not re_password:
            response = jsonify({'error': 'Please confirm your password'})
            return response, 400

        # Then validate formats and matches
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
            hashed_password = enc.hash_password(password)
            insert_query = """
                INSERT INTO users (uName, email, password, created_at, last_login)
                VALUES (%s, %s, %s, %s, %s)
            """
            
            cursor.execute(insert_query, (username, email, hashed_password, datetime.now(), datetime.now()))
            connection.commit()
            
            user_id = cursor.lastrowid
            
            session['user_id'] = user_id
            session['username'] = username
            
            response = jsonify({
                'success': True,
                'message': 'User registered successfully',
                'user': {
                    'user_id': user_id,
                    'username': username,
                    'email': email
                }
            })
            return response, 201
            
        except Error as e:
            connection.rollback()  # Rollback on error
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

@app.route('/api/auth/signout', methods=['POST'])
def api_signout():
    """API endpoint for user signout"""
    try:
        # Clear session data
        session.pop('user_id', None)
        session.pop('username', None)
        
        response = jsonify({
            'success': True,
            'message': 'User signed out successfully'
        })
        
        # Add security headers
        # add_security_headers(response)
        
        return response, 200
        
    except Exception as e:
        logger.error(f"Signout error: {e}")
        response = jsonify({'error': 'Signout failed'})
        
        return response, 500

@app.route('/api/vault', methods=['GET', 'OPTIONS'])
@require_auth
def get_vault_credentials():
    """Get all credentials for the authenticated user"""
    
    # Handle OPTIONS request for CORS
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        # Get the authenticated user_id from the decorator
        user_id = request.current_user_id
        
        # Get database connection
        connection = get_db_connection()
        if not connection:
            logger.error("Database connection failed for vault access")
            return jsonify({
                'success': False,
                'error': 'Service temporarily unavailable'
            }), 503
        
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Select only necessary fields for vault page
            query = """
                SELECT
                    id,
                    user_id,
                    credential_website,
                    credential_username,
                    credential_password
                FROM credentials
                WHERE user_id = %s
                ORDER BY id ASC
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
            
            return jsonify({
                'success': True,
                'message': f'Retrieved {len(credentials)} credentials',
                'data': credentials,
                'total_count': len(credentials),
                'user_id': user_id
            }), 200
            
        except Exception as db_error:
            logger.error(f"Database error in vault access for user {user_id}: {str(db_error)}")
            return jsonify({
                'success': False,
                'error': 'Failed to retrieve credentials'
            }), 500
            
        finally:
            if 'cursor' in locals():
                cursor.close()
            if connection:
                connection.close()
                
    except Exception as e:
        logger.error(f"Unexpected error in vault endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route('/api/credential/decrypt/<int:c_id>', methods=['GET'])
@require_auth
def decrypt_password(c_id):
    """Decrypt a password for the authenticated user"""
    try:
        # Get the authenticated user_id from the decorator
        user_id = request.current_user_id
        
        # Get database connection
        connection = get_db_connection()
        if not connection:
            logger.error("Database connection failed for vault access")
            return jsonify({
                'success': False,
                'error': 'Service temporarily unavailable'
            }), 503
        
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Validate owner of the credential
            validate_query = """
                SELECT
                    id, credential_password
                FROM credentials 
                WHERE id = %s AND user_id = %s
                LIMIT 1
            """
            cursor.execute(validate_query, (c_id, user_id))
            credential = cursor.fetchone()
            
            if not credential:
                return jsonify({
                    'success': False,
                    'error': 'Credential not found'
                }), 404
            
            # Decrypt the password
            decrypted_password = enc.decrypt_password(credential['credential_password'], AES_secret_key)
            
            return jsonify({
                'success': True,
                'message': f'Decrypted password for credential {c_id}',
                'data': {
                    'credential_id': c_id,
                    'decrypted_password': decrypted_password
                }
            }), 200
            
        except Exception as db_error:
            logger.error(f"Database error in vault access for user {user_id}: {str(db_error)}")
            return jsonify({
                'success': False,
                'error': 'Failed to decrypt password'
            }), 500
            
        finally:
            if 'cursor' in locals():
                cursor.close()
            if connection:
                connection.close()
    except Exception as e:
        logger.error(f"Unexpected error in vault endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route('/api/credential', methods=['POST'])
@require_auth
def add_credential():
    """Add a new credential for the authenticated user"""
    try:
        data = request.get_json()
        
        # Validate JSON data
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON data'}), 400
        
        # Get the authenticated user_id from the decorator
        user_id = request.current_user_id
        
        # Get database connection
        connection = get_db_connection()
        if not connection:
            logger.error("Database connection failed for vault access")
            return jsonify({
                'success': False,
                'error': 'Service temporarily unavailable'
            }), 503

        try:
            cursor = connection.cursor(dictionary=True)
            
            # Validate input data
            if not data.get('credential_website') or not data.get('credential_username') or not data.get('credential_password'):
                return jsonify({
                    'success': False, 
                    'error': 'Website, username, and password are required'
                }), 400
            
            # Validate if the credential already exists for the user
            validate_query = """
                SELECT
                    id
                FROM credentials 
                WHERE user_id = %s AND credential_website = %s AND credential_username = %s
                LIMIT 1
            """
            cursor.execute(validate_query, (user_id, data.get('credential_website', ''), data.get('credential_username', '')))
            credential = cursor.fetchone()
            
            if credential:
                return jsonify({
                    'success': False,
                    'error': 'Credential already exists for this user with the same website and username'
                }), 409
            
            # Validate the requested user
            if str(user_id).strip() != str(data.get('user_id')).strip():
                logger.warning(f"Unauthorized access attempt to add credential by user {user_id}")
                return jsonify({
                    'success': False,
                    'error': 'Unauthorized access to credential'
                }), 403

            # Insert new credential
            insert_query = """
                INSERT INTO credentials (user_id, credential_website, credential_username, credential_password, created_at, created_ip_address)
                VALUES (%s, %s, %s, %s, %s, %s)
            """

            datetime_now = datetime.now()
            encrypted_password = enc.encrypt_password(data.get('credential_password', ''), AES_secret_key)
            ip_address = get_client_ip(request)

            cursor.execute(insert_query, (
                int(user_id),
                data.get('credential_website', ''),
                data.get('credential_username', ''),
                encrypted_password,
                datetime_now,
                ip_address  # Store the IP address of the request
            ))
            connection.commit()
            
            new_credential_id = cursor.lastrowid
            
            # Log successful addition
            logger.info(f"User {user_id} added new credential with ID {new_credential_id}")
            
            return jsonify({
                'success': True,
                'message': f'Credential added successfully with ID {new_credential_id}',
                'data': {
                    'credential_id': new_credential_id,
                    'user_id': user_id,
                    'encrypted_password': encrypted_password,
                }
            }), 201
            
        except Exception as db_error:
            logger.error(f"Database error in vault access for user {user_id}: {db_error}")
            logger.exception(f"Database error in vault access for user {user_id}: {db_error}")
            return jsonify({
                'success': False,
                'error': 'Failed to add credential'
            }), 500
            
        finally:
            if 'cursor' in locals():
                cursor.close()
            if connection:
                connection.close()
                
    except Exception as e:
        logger.error(f"Unexpected error in vault endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route('/api/credential/<int:c_id>', methods=['PUT'])
@require_auth
def update_credential(c_id):
    """Update a credential for the authenticated user"""
    try:
        data = request.get_json()
        
        # Validate JSON data
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON data'}), 400
        
        # Get the authenticated user_id from the decorator
        user_id = request.current_user_id
        
        # Get database connection
        connection = get_db_connection()
        if not connection:
            logger.error("Database connection failed for vault access")
            return jsonify({
                'success': False,
                'error': 'Service temporarily unavailable'
            }), 503

        try:
            cursor = connection.cursor(dictionary=True)
            
            # Validate input data
            if not data.get('credential_website') or not data.get('credential_username') or not data.get('credential_password'):
                return jsonify({
                    'success': False, 
                    'error': 'Website, username, and password are required'
                }), 400
            
            # Validate if the credential already exists for the user
            validate_query = """
                SELECT
                    credential_website
                FROM credentials 
                WHERE user_id = %s AND id = %s
                LIMIT 1
            """
            cursor.execute(validate_query, (user_id, c_id))
            credential = cursor.fetchone()
            
            if not credential:
                return jsonify({
                    'success': False,
                    'error': 'Credential already exists for this user with the same website and username'
                }), 409
            
            # Validate the requested user
            if str(user_id).strip() != str(data.get('user_id')).strip():
                logger.warning(f"Unauthorized access attempt to update credential by user {user_id}")
                return jsonify({
                    'success': False,
                    'error': 'Unauthorized access to credential'
                }), 403

            # Insert new credential
            update_query = """
                UPDATE credentials
                SET credential_website = %s, credential_username = %s, credential_password = %s, updated_at = %s
                WHERE id = %s AND user_id = %s
            """

            datetime_now = datetime.now()
            encrypted_password = enc.encrypt_password(data.get('credential_password', ''), AES_secret_key)

            cursor.execute(update_query, (
                data.get('credential_website', ''),
                data.get('credential_username', ''),
                encrypted_password,
                datetime_now,
                c_id,
                user_id
            ))
            connection.commit()
            
            # Log successful addition
            logger.info(f"User {user_id} updated new credential with ID {c_id}")
            
            return jsonify({
                'success': True,
                'message': f'Credential updated successfully with ID {c_id}',
                'data': {
                    'credential_id': c_id,
                    'user_id': user_id,
                    'encrypted_password': encrypted_password,
                }
            }), 201
            
        except Exception as db_error:
            logger.error(f"Database error in vault access for user {user_id}: {str(db_error)}")
            return jsonify({
                'success': False,
                'error': 'Failed to update credential'
            }), 500
            
        finally:
            if 'cursor' in locals():
                cursor.close()
            if connection:
                connection.close()
                
    except Exception as e:
        logger.error(f"Unexpected error in vault endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route('/api/credential/<int:c_id>', methods=['DELETE'])
@require_auth
def delete_credential(c_id):
    """Delete a credential for the authenticated user"""
    try:
        # Get the authenticated user_id from the decorator
        user_id = request.current_user_id
        
        # Get database connection
        connection = get_db_connection()
        if not connection:
            logger.error("Database connection failed for vault access")
            return jsonify({
                'success': False,
                'error': 'Service temporarily unavailable'
            }), 503
        
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Validate owner of the credential
            validate_query = """
                SELECT
                    id
                FROM credentials 
                WHERE id = %s AND user_id = %s
                LIMIT 1
            """
            cursor.execute(validate_query, (c_id, user_id))
            credential = cursor.fetchone()
            
            if not credential:
                return jsonify({
                    'success': False,
                    'error': 'Credential not found'
                }), 404
            
            # Validate the requested user
            validate_query = """
                SELECT
                    user_id
                FROM credentials
                WHERE id = %s
                LIMIT 1
            """
            cursor.execute(validate_query, (c_id))
            credential = cursor.fetchone()

            if str(user_id).strip() != str(credential['user_id']).strip():
                logger.warning(f"Unauthorized access attempt to delete credential {c_id} by user {user_id}")
                return jsonify({
                    'success': False,
                    'error': 'Unauthorized access to credential'
                }), 403
            
            # Now delete the credential
            delete_query = """
                DELETE FROM credentials
                WHERE id = %s AND user_id = %s
            """

            cursor.execute(delete_query, (c_id, user_id))
            connection.commit()
            
            # Log authorized access attempts
            logger.info(f"User {user_id} delete credential {c_id}")

            return jsonify({
                'success': True,
                'message': 'Credential deleted successfully'
            }), 200
            
        except Exception as db_error:
            logger.error(f"Database error in vault access for user {user_id}: {str(db_error)}")
            return jsonify({
                'success': False,
                'error': 'Failed to retrieve credentials'
            }), 500
            
        finally:
            if 'cursor' in locals():
                cursor.close()
            if connection:
                connection.close()
                
    except Exception as e:
        logger.error(f"Unexpected error in vault endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route('/api/generate-password', methods=['GET'])
@require_auth
def generate_password():
    """Generate a random password"""
    try:
        # Get the authenticated user_id from the decorator
        user_id = request.current_user_id
        
        generation_method = request.args.get('method')
        logger.info(f"User {user_id} requested password generation with method: {generation_method}")
        if not generation_method:
            logger.error(f"User {user_id} did not specify a password generation method")
            return jsonify({'success': False, 'error': 'Password generation method is required'}), 400
        
        # Get the password generation parameters
        no_words = request.args.get('noWords', 4, type=int)
        no_words_to_special_char = request.args.get('noWordsToSpecialChar', 4, type=int)
        min_length = request.args.get('minLength', 8, type=int)
        max_length = request.args.get('maxLength', 16, type=int)
        cap = request.args.get('cap', 'true').lower() == 'true'
        non_cap = request.args.get('nonCap', 'true').lower() == 'true'
        special_char = request.args.get('specialChar', 'true').lower() == 'true'
        
        # Validate that at least one character type is selected
        if not cap and not non_cap and not special_char:
            logger.error(f"User {user_id} did not select any character types for password generation")
            return jsonify({'success': False, 'error': 'At least one character type must be selected'}), 400
        
        # Validate length parameters
        if min_length < 1 or max_length < 1 or min_length > max_length:
            logger.error(f"User {user_id} provided invalid length parameters: minLength={min_length}, maxLength={max_length}")
            return jsonify({'success': False, 'error': 'Invalid length parameters'}), 400

        if (generation_method == 'passphrase'):
            # Generate a passphrase
            password = pg.passphrase_generator(
                noWords=no_words, 
                noWordsToSpecialChar = no_words_to_special_char,
                capAlphabet=cap, 
                lowerAlphabet=non_cap, 
                specialChar=special_char
            )

            logger.info(f"User {user_id} generated new PASSPHRASE password")
            return jsonify({
                'success': True,
                'message': f'Password generated successfully by user {user_id}',
                'data': {
                    'user_id': user_id,
                    'password': password,
                }
            }), 201
        
        elif (generation_method == 'default'):
            # Generate a default password
            password = pg.password_generator(
                maxLength=max_length, 
                minLength=min_length, 
                capAlphabet=cap, 
                lowerAlphabet=non_cap, 
                specialChar=special_char
            )

            logger.info(f"User {user_id} generated new DEFAULT password")
            return jsonify({
                'success': True,
                'message': f'Password generated successfully by user {user_id}',
                'data': {
                    'user_id': user_id,
                    'password': password,
                }
            }), 201
                
    except Exception as e:
        logger.error(f"Unexpected error in vault endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500
    
@app.route('/api/password-health', methods=['GET', 'OPTIONS'])
@require_auth
def password_health():
    """ Password health """

    # Handle OPTIONS request for CORS
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        # Get the authenticated user_id from the decorator
        user_id = request.current_user_id
        
        # Get database connection
        connection = get_db_connection()
        if not connection:
            logger.error("Database connection failed for vault access")
            return jsonify({
                'success': False,
                'error': 'Service temporarily unavailable'
            }), 503
        
        try:
            duplicates = ph.process_credentials_for_duplicates(
                connection, user_id, enc, max_workers=4
            )
         
            if duplicates:
                logger.info(f"Found {len(duplicates)} groups of duplicate passwords for user {user_id}")
                return jsonify({
                    'success': True,
                    'user_id': user_id,
                    'duplicate': duplicates,
                    'duplicates_found': len(duplicates)
                }), 200
            
            else:
                return jsonify({
                    'success': True,
                    'user_id': user_id,
                    'duplicate_groups': {},
                    'duplicates_found': 0
                })
            
        except Exception as db_error:
            logger.error(f"Database error in vault access for user {user_id}: {str(db_error)}")
            return jsonify({
                'success': False,
                'error': 'Failed to retrieve credentials'
            }), 500
                
    except Exception as e:
        logger.error(f"Unexpected error in vault endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Get fresh values from bcc functions (don't rely on cached globals for health check)
        current_address, current_key = bcc.load_account()
        current_contract = bcc.load_contract()
        
        is_connected = w3.is_connected()
        balance = 0
        
        if current_address:
            try:
                balance = w3.eth.get_balance(current_address)
            except Exception as e:
                logger.warning(f"Could not get balance: {e}")
        
        return jsonify({
            'success': True,
            'status': 'healthy',
            'blockchain_connected': is_connected,
            'account_address': current_address,
            'account_balance': str(w3.from_wei(balance, 'ether')) + ' ETH' if balance else '0 ETH',
            'contract_loaded': current_contract is not None,
            'chain_id': w3.eth.chain_id if is_connected else None
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/api/audit-trail', methods=['POST'])
@require_auth
@validate_request_data(
    required_fields=['userID', 'credID', 'activityName', 'date', 'ip'],
    validation_rules={
        'userID': validate_user_id,
        'credID': validate_cred_id,
        'activityName': validate_activity_name,
        'date': validate_date,
        'ip': validate_ip
    }
)
def create_activity_log(validated_data):
    """Create a new activity log for the authenticated user"""
    try:
        # Ensure we have account and contract loaded
        if not account_address or not private_key or not contract:
            logger.error("Account or contract not initialized")
            return jsonify({
                'success': False,
                'error': 'System not properly initialized',
                'code': 'INITIALIZATION_ERROR'
            }), 500
        
        # Check if log with this credID already exists
        exists = contract.functions.activityLogExists(validated_data['credID']).call()
        if exists:
            return jsonify({
                'success': False,
                'error': 'Activity log with this credID already exists',
                'code': 'DUPLICATE_CRED_ID'
            }), 409
        
        # Build transaction
        txn = contract.functions.createActivityLog(
            validated_data['userID'],
            validated_data['credID'],
            validated_data['activityName'],
            validated_data['date'],
            validated_data['ip']
        ).build_transaction({
            'chainId': CHAIN_ID,
            'gas': 500000,
            'gasPrice': w3.to_wei('20', 'gwei'),
            'nonce': w3.eth.get_transaction_count(account_address),
        })
        
        # Sign and send transaction
        signed_txn = w3.eth.account.sign_transaction(txn, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        
        # Wait for transaction receipt
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        
        # Get the generated log ID from transaction logs
        log_id = None
        for log in tx_receipt.logs:
            try:
                decoded_log = contract.events.ActivityLogCreated().process_log(log)
                log_id = decoded_log['args']['logID']
                break
            except:
                continue
        
        logger.info(f"Activity log created: {log_id}")
        
        return jsonify({
            'success': True,
            'message': 'Activity log created successfully',
            'data': {
                'logID': log_id,
                'credID': validated_data['credID'],
                'transaction_hash': tx_hash.hex(),
                'block_number': tx_receipt.blockNumber,
                'gas_used': tx_receipt.gasUsed
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating activity log: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to create activity log',
            'details': str(e),
            'code': 'CREATION_ERROR'
        }), 500

# def create_activity_log():
#     try:
#         user_id = request.current_user_id
#         cred_id = data.get('cred_id')
        
#         data = request.get_json()
        
#         # Validate required fields
#         required_fields = ['activity_name']
#         for field in required_fields:
#             if field not in data:
#                 return jsonify({"error": f"Missing required field: {field}"}), 400
        
#         # Prepare arguments for chaincode
#         args = [
#             user_id,
#             cred_id,
#             data['activity_name'],
#             datetime.now(),
#             get_client_ip
#         ]
        
#         # Invoke chaincode
#         result = fabric_client.invoke_chaincode('CreateActivityLog', args)
        
#         if 'error' in result:
#             return jsonify(result), 500
        
#         return jsonify({
#             "success": True,
#             "id": log_id,
#             "tx_id": result.get('tx_id'),
#             "message": "Activity log created successfully"
#         }), 201
        
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

@app.route('/api/activity/<user_id>', methods=['GET'])
@require_auth
def get_activity_log_by_user(user_id):
    """Get all activity logs for specific user from blockchain"""
    try:
        # Ensure contract is loaded
        if not contract:
            logger.error("Contract not initialized")
            return jsonify({
                'success': False,
                'error': 'Contract not initialized',
                'code': 'CONTRACT_ERROR'
            }), 500
        
        # Validate user_id
        is_valid, error_msg = validate_user_id(user_id)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': error_msg,
                'code': 'INVALID_USER_ID'
            }), 400
        
        # Get user's log details
        log_details = contract.functions.getActivityLogDetailsByUser(user_id).call()
        
        # Structure the response
        logs = []
        for i in range(len(log_details[0])):  # log_details[0] is logIDs array
            logs.append({
                'logID': log_details[0][i],
                'credID': log_details[1][i],
                'activityName': log_details[2][i],
                'date': log_details[3][i],
                'ip': log_details[4][i],
                'timestamp': log_details[5][i]
            })
        
        return jsonify({
            'success': True,
            'data': {
                'userID': user_id,
                'total_logs': len(logs),
                'logs': logs
            }
        })
        
    except Exception as e:
        logger.error(f"Error retrieving user activity logs: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve user activity logs',
            'details': str(e),
            'code': 'USER_LOGS_ERROR'
        }), 500

# def get_activity_logs_by_user(user_id):
#     """Get all activity logs for a specific user"""
#     try:
#         result = fabric_client.query_chaincode('GetActivityLogsByUser', [user_id])
        
#         if 'error' in result:
#             return jsonify({"result": result}), 500
        
#         return jsonify({"result": result})
        
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'code': 'NOT_FOUND'
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'success': False,
        'error': 'Method not allowed',
        'code': 'METHOD_NOT_ALLOWED'
    }), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'code': 'INTERNAL_ERROR'
    }), 500

if __name__ == '__main__':
    # Initialize database on startup
    # init_database()
    app.run(port=9011, debug=True)