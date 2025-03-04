from flask import Flask, request, send_file, render_template, redirect, url_for, flash, session
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import uuid
from werkzeug.utils import secure_filename
import logging
from datetime import datetime, timedelta
import shutil
import time
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("enclypt.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("enclypt")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")  # Better to use environment variable
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # Increased limit to 50MB
app.config['TEMP_FILE_LIFETIME'] = 30  # Minutes to keep decrypted files

# Configuration
UPLOAD_FOLDER = "uploads"
KEY_FOLDER = "keys"
TEMP_FOLDER = "temp"
for folder in [UPLOAD_FOLDER, KEY_FOLDER, TEMP_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Function to derive encryption key from password
def derive_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return salt, key

# Function to generate or load encryption key
def load_key(key_id=None, password=None):
    if key_id is None:
        # Generate a new key
        key_id = str(uuid.uuid4())
        
        if password:
            # Derive key from password
            salt, key = derive_key_from_password(password)
            # Store salt for future key derivation
            salt_path = os.path.join(KEY_FOLDER, f"{key_id}.salt")
            with open(salt_path, "wb") as salt_file:
                salt_file.write(salt)
        else:
            # Generate random key
            key = Fernet.generate_key()
            
        # Store key ID for reference
        key_path = os.path.join(KEY_FOLDER, f"{key_id}.key")
        with open(key_path, "wb") as key_file:
            key_file.write(key)
        logger.info(f"Generated new key with ID: {key_id}")
    else:
        # Load existing key
        key_path = os.path.join(KEY_FOLDER, f"{key_id}.key")
        salt_path = os.path.join(KEY_FOLDER, f"{key_id}.salt")
        
        if not os.path.exists(key_path):
            logger.error(f"Key not found: {key_id}")
            return None, None
            
        # Check if this is a password-protected key
        is_password_protected = os.path.exists(salt_path)
        
        if is_password_protected:
            # This is a password-protected key
            if not password:
                logger.error(f"Password required for key: {key_id} but not provided")
                return key_id, None
                
            with open(salt_path, "rb") as salt_file:
                salt = salt_file.read()
            _, key = derive_key_from_password(password, salt)
        else:
            # Regular key
            with open(key_path, "rb") as key_file:
                key = key_file.read()
                
        logger.info(f"Loaded key with ID: {key_id}")
    
    try:
        cipher = Fernet(key)
        return key_id, cipher
    except Exception as e:
        logger.error(f"Error creating cipher: {str(e)}")
        return key_id, None
# Routes
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/encrypt')
def encrypt_page():
    return render_template("encrypt.html")

@app.route('/decrypt')
def decrypt_page():
    return render_template("decrypt.html")

@app.route('/about')
def about():
    return render_template("about.html")

# File upload and encryption
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash("No file selected!", "error")
        return redirect(url_for('encrypt_page'))
    
    file = request.files['file']
    if file.filename == '':
        flash("No selected file!", "error")
        return redirect(url_for('encrypt_page'))
    
    # Get password if provided
    password = request.form.get('password', '')
    
    # Generate secure filename
    filename = secure_filename(file.filename)
    
    # Read file data
    file_data = file.read()
    
    # Generate key and encrypt data
    key_id, cipher = load_key(password=password if password else None)
    encrypted_data = cipher.encrypt(file_data)
    
    # Save encrypted file
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    encrypted_filename = f"{timestamp}_{filename}.enc"
    encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)
    
    with open(encrypted_path, "wb") as enc_file:
        enc_file.write(encrypted_data)
    
    # Store the key ID in session
    session['last_key_id'] = key_id
    session['last_filename'] = encrypted_filename
    
    # Track file size
    file_size = len(file_data) / 1024  # Size in KB
    
    logger.info(f"Encrypted file: {filename} -> {encrypted_filename} ({file_size:.2f} KB)")
    flash(f"File encrypted successfully!", "success")
    return render_template("download.html", 
                          filename=encrypted_filename, 
                          key_id=key_id, 
                          original_filename=filename,
                          is_password_protected=bool(password))

# File decryption and download
@app.route('/decrypt-file', methods=['POST'])
def decrypt_file():
    # Get the key ID and password if provided
    key_id = request.form.get("key_id")
    password = request.form.get("password", "")
    
    if 'file' not in request.files:
        flash("No file selected!", "error")
        return redirect(url_for('decrypt_page'))
    
    file = request.files['file']
    if file.filename == '':
        flash("No selected file!", "error")
        return redirect(url_for('decrypt_page'))
    
    # Validate the file has .enc extension
    if not file.filename.endswith(".enc"):
        flash("Invalid encrypted file! Must have .enc extension.", "error")
        return redirect(url_for('decrypt_page'))
    
    # Read the encrypted data
    encrypted_data = file.read()
    
    # Check if the file is password-protected
    salt_path = os.path.join(KEY_FOLDER, f"{key_id}.salt")
    is_password_protected = os.path.exists(salt_path)
    
    # If user provided a password for a non-password-protected file, notify them
    if password and not is_password_protected:
        flash("Note: This file is not password protected. Proceeding with decryption using the key ID.", "info")
    
    # Load the key and decrypt
    _, cipher = load_key(key_id, password if is_password_protected else None)
    if cipher is None:
        flash("Invalid decryption key or password!", "error")
        return redirect(url_for('decrypt_page'))
    
    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Generate decrypted filename
        original_filename = file.filename[:-4]  # Remove .enc
        if '_' in original_filename:
            # Remove timestamp if present
            original_filename = original_filename.split('_', 1)[1]
        
        # Create temporary file for download with unique ID
        temp_id = str(uuid.uuid4())
        temp_dir = os.path.join(TEMP_FOLDER, temp_id)
        os.makedirs(temp_dir, exist_ok=True)
        
        temp_path = os.path.join(temp_dir, original_filename)
        with open(temp_path, "wb") as dec_file:
            dec_file.write(decrypted_data)
        
        # Store temp info in session for cleanup
        if 'temp_files' not in session:
            session['temp_files'] = []
        
        session['temp_files'].append({
            'path': temp_dir,
            'expires': (datetime.now() + timedelta(minutes=app.config['TEMP_FILE_LIFETIME'])).timestamp()
        })
        
        file_size = len(decrypted_data) / 1024  # Size in KB
        logger.info(f"Decrypted file: {file.filename} -> {original_filename} ({file_size:.2f} KB)")
        return send_file(temp_path, as_attachment=True, download_name=original_filename)
    
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        flash("Decryption failed! Invalid key/password or corrupted file.", "error")
        return redirect(url_for('decrypt_page'))
# Download encrypted file
@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        flash("File not found!", "error")
        return redirect(url_for('encrypt_page'))
    return send_file(file_path, as_attachment=True)

# Generate QR code for key sharing
@app.route('/key-qr/<key_id>')
def key_qr(key_id):
    # This would generate a QR code for the key ID
    # Additional implementation needed
    pass

@app.route('/check-temp-files')
def check_temp_files():
    """API endpoint to clean up expired temporary files"""
    if 'temp_files' in session:
        cleanup_temp_files()
    return "", 204  # No content response

@app.errorhandler(413)
def request_entity_too_large(error):
    flash(f"File too large! Maximum size is {app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024):.0f}MB.", "error")
    return redirect(url_for('encrypt_page'))

# Clean up temporary files
def cleanup_temp_files():
    """Remove expired temporary files"""
    now = datetime.now().timestamp()
    if 'temp_files' in session:
        remaining_files = []
        for file_info in session['temp_files']:
            if file_info['expires'] < now:
                # Remove expired file
                try:
                    if os.path.exists(file_info['path']):
                        shutil.rmtree(file_info['path'])
                        logger.info(f"Removed temp directory: {file_info['path']}")
                except Exception as e:
                    logger.error(f"Error removing temp file: {str(e)}")
            else:
                remaining_files.append(file_info)
        
        session['temp_files'] = remaining_files

# Background cleanup task
def background_cleanup():
    """Background thread to periodically cleanup old files"""
    while True:
        # Delete files in UPLOAD_FOLDER older than 7 days
        now = time.time()
        for folder in [UPLOAD_FOLDER, TEMP_FOLDER]:
            for filename in os.listdir(folder):
                file_path = os.path.join(folder, filename)
                if os.path.isfile(file_path):
                    # Skip if the file is less than 7 days old
                    if now - os.path.getmtime(file_path) < 7 * 86400:
                        continue
                    try:
                        os.remove(file_path)
                        logger.info(f"Removed old file: {file_path}")
                    except Exception as e:
                        logger.error(f"Error removing old file {file_path}: {str(e)}")
                elif os.path.isdir(file_path) and folder == TEMP_FOLDER:
                    # For temp folder, also check directories
                    if now - os.path.getmtime(file_path) < 1 * 86400:  # 1 day for temp dirs
                        continue
                    try:
                        shutil.rmtree(file_path)
                        logger.info(f"Removed old temp directory: {file_path}")
                    except Exception as e:
                        logger.error(f"Error removing temp directory {file_path}: {str(e)}")
                        
        # Sleep for 1 hour before next check
        time.sleep(3600)

if __name__ == '__main__':
    # Start background cleanup thread
    cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
    cleanup_thread.start()
    
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 7500)))