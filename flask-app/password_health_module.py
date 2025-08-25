from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import logging
import os
import mysql.connector
from mysql.connector import Error
import mysql
import zxcvbn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_credentials_batch(connection, user_id, batch_size=25):
    """
    Generator function to fetch credentials in batches
    """
    cursor = connection.cursor(dictionary=True)
    
    try:
        # First, get total count for this user
        count_query = "SELECT COUNT(*) as total FROM credentials WHERE user_id = %s"
        cursor.execute(count_query, (user_id,))
        total_records = cursor.fetchone()['total']
        
        if total_records == 0:
            return
        
        logger.info(f"Processing {total_records} credentials for user {user_id}")
        
        # Fetch records in batches
        offset = 0
        while offset < total_records:
            query = """
                SELECT
                    id,
                    credential_password
                FROM credentials
                WHERE user_id = %s
                LIMIT %s OFFSET %s
            """
            
            cursor.execute(query, (user_id, batch_size, offset))
            batch = cursor.fetchall()
            
            if not batch:
                break
            
            logger.info(f"Fetched batch: {offset + 1} to {offset + len(batch)}")
            yield batch  # Return this batch
            offset += len(batch)
            
    except mysql.connector.Error as e:
        logger.error(f"Database error: {e}")
        raise
    finally:
        cursor.close()

def process_credentials_for_duplicates(connection, user_id, encryption_module, max_workers=4):
    """
    Process credentials to find duplicates with proper batching and threading
    """
    password_credentials = defaultdict(list)
    weak_password = set()
    dup_password = set()
    
    # Process each batch
    for batch in fetch_credentials_batch(connection, user_id, batch_size=25):
        # Process batch with threading
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit decryption jobs
            future_to_credential = {
                executor.submit(decrypt_credential_safe, encryption_module, record['credential_password']): record
                for record in batch  # 'record' is each dictionary in the batch
            }
            
            # Collect results
            for future in future_to_credential:
                credential_record = future_to_credential[future]
                try:
                    decrypted_password = future.result()
                    if decrypted_password:
                        password_credentials[decrypted_password].append(credential_record['id'])

                        if password_strength_checker(decrypted_password) <= 2:
                            weak_password.add(decrypted_password)

                except Exception as e:
                    logger.error(f"Error processing credential ID {credential_record['id']}: {e}")
    
    for password, credential_ids in password_credentials.items():
        if len(credential_ids) > 1:
            dup_password.add(password)

    duplicate_weak = []
    problematic_passwords = weak_password.union(dup_password)
    
    for password in problematic_passwords:
        duplicate_weak.extend(password_credentials[password])
   
    return duplicate_weak

def decrypt_credential_safe(encryption_module, encrypted_password):
    """
    Safely decrypt a credential password with error handling
    """
    try:
        return encryption_module.decrypt_password(encrypted_password, bytes.fromhex(os.getenv('AES_SECRET_KEY')))
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None
    
def password_strength_checker(password):
    """
    Check the strength of a password based on length and character variety
    """
    result = zxcvbn.zxcvbn(password)

    return result['score']