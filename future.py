from flask import Flask, request, send_file, render_template, redirect, url_for, flash, session, jsonify, Response
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
import base64
import uuid
from werkzeug.utils import secure_filename
import logging
from datetime import datetime, timedelta
import shutil
import time
import threading
import json
import sqlite3
from functools import wraps
import secrets
import hmac
from io import BytesIO
import zipfile
from urllib.parse import urljoin
import hashlib
import qrcode
import io
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ================ Configuration ================
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
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))  # More secure default
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Increased limit to 100MB
app.config['TEMP_FILE_LIFETIME'] = 30  # Minutes to keep decrypted files
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session timeout
app.config['USE_ARGON2'] = os.environ.get("USE_ARGON2", "False").lower() == "true"
app.config['PBKDF2_ITERATIONS'] = int(os.environ.get("PBKDF2_ITERATIONS", "310000"))  # Updated OWASP recommendation
app.config['ENCRYPTION_CHUNK_SIZE'] = 4 * 1024 * 1024  # 4MB chunks for processing large files
app.config['ENABLE_EMAIL'] = os.environ.get("ENABLE_EMAIL", "False").lower() == "true"
app.config['EMAIL_SERVER'] = os.environ.get("EMAIL_SERVER", "smtp.example.com")
app.config['EMAIL_PORT'] = int(os.environ.get("EMAIL_PORT", "587"))
app.config['EMAIL_USER'] = os.environ.get("EMAIL_USER", "")
app.config['EMAIL_PASSWORD'] = os.environ.get("EMAIL_PASSWORD", "")
app.config['EMAIL_FROM'] = os.environ.get("EMAIL_FROM", "enclypt@example.com")
app.config['BASE_URL'] = os.environ.get("BASE_URL", "http://localhost:7500")
app.config['RATE_LIMIT_REQUESTS'] = int(os.environ.get("RATE_LIMIT_REQUESTS", "50"))
app.config['RATE_LIMIT_WINDOW'] = int(os.environ.get("RATE_LIMIT_WINDOW", "3600"))  # In seconds (1 hour)

# Directories
UPLOAD_FOLDER = "uploads"
KEY_FOLDER = "keys"
TEMP_FOLDER = "temp"
DB_FOLDER = "db"
for folder in [UPLOAD_FOLDER, KEY_FOLDER, TEMP_FOLDER, DB_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Initialize database
DB_PATH = os.path.join(DB_FOLDER, "enclypt.db")

# ================ Database Setup ================
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        
        # Keys table stores metadata about encryption keys
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            id TEXT PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_password_protected BOOLEAN,
            name TEXT,
            metadata TEXT
        )
        ''')
        
        # Files table for tracking encrypted files
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            original_filename TEXT,
            encrypted_filename TEXT,
            key_id TEXT,
            size_bytes INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            metadata TEXT,
            FOREIGN KEY (key_id) REFERENCES keys(id)
        )
        ''')
        
        # Access logs for audit purposes
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action TEXT,
            file_id TEXT,
            key_id TEXT,
            ip_address TEXT,
            user_agent TEXT,
            success BOOLEAN
        )
        ''')
        
        # Shared keys for time-limited sharing
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_keys (
            share_id TEXT PRIMARY KEY,
            key_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            access_count INTEGER DEFAULT 0,
            max_access INTEGER,
            FOREIGN KEY (key_id) REFERENCES keys(id)
        )
        ''')
        
        # Rate limiting table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS rate_limits (
            ip_address TEXT PRIMARY KEY,
            request_count INTEGER,
            window_start TIMESTAMP
        )
        ''')
        
        conn.commit()

# Initialize database on startup
init_db()

# ================ Utility Functions ================
# Generate CSRF token
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# CSRF protection decorator
def csrf_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = session.get('csrf_token')
            if not token or token != request.form.get('csrf_token'):
                flash('CSRF validation failed', 'error')
                return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Rate limiting decorator
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        now = datetime.now()
        
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT request_count, window_start FROM rate_limits WHERE ip_address = ?', (ip,))
            result = cursor.fetchone()
            
            if result:
                count, window_start = result
                window_start = datetime.fromisoformat(window_start)
                
                # Reset counter if window has expired
                if now - window_start > timedelta(seconds=app.config['RATE_LIMIT_WINDOW']):
                    cursor.execute('UPDATE rate_limits SET request_count = 1, window_start = ? WHERE ip_address = ?', 
                                  (now.isoformat(), ip))
                    conn.commit()
                # Check if rate limit exceeded
                elif count >= app.config['RATE_LIMIT_REQUESTS']:
                    logger.warning(f"Rate limit exceeded for IP: {ip}")
                    return jsonify({"error": "Rate limit exceeded"}), 429
                # Increment counter
                else:
                    cursor.execute('UPDATE rate_limits SET request_count = request_count + 1 WHERE ip_address = ?', (ip,))
                    conn.commit()
            else:
                # First request from this IP
                cursor.execute('INSERT INTO rate_limits (ip_address, request_count, window_start) VALUES (?, 1, ?)', 
                              (ip, now.isoformat()))
                conn.commit()
        
        return f(*args, **kwargs)
    return decorated_function

# Log access for audit purposes
def log_access(action, file_id=None, key_id=None, success=True):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO access_logs (action, file_id, key_id, ip_address, user_agent, success)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (action, file_id, key_id, request.remote_addr, request.user_agent.string, success))
            conn.commit()
    except Exception as e:
        logger.error(f"Error logging access: {str(e)}")

# Email notification function
def send_email_notification(to_email, subject, message):
    if not app.config['ENABLE_EMAIL']:
        logger.info(f"Email notifications disabled. Would have sent to {to_email}: {subject}")
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = app.config['EMAIL_FROM']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(message, 'plain'))
        
        server = smtplib.SMTP(app.config['EMAIL_SERVER'], app.config['EMAIL_PORT'])
        server.starttls()
        server.login(app.config['EMAIL_USER'], app.config['EMAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email notification sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False

# ================ Cryptography Functions ================
# Function to derive encryption key from password
def derive_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    if app.config['USE_ARGON2']:
        try:
            from argon2 import PasswordHasher
            from argon2.low_level import Type
            
            # Argon2id with parameters recommended by OWASP
            ph = PasswordHasher(
                time_cost=4,      # Iterations
                memory_cost=65536,  # 64MB
                parallelism=4,    # 4 threads
                hash_len=32,      # 32 bytes output
                type=Type.ID      # Argon2id variant
            )
            
            # Salt is automatically handled by Argon2
            hash_result = ph.hash(password)
            
            # Get raw hash bytes and encode properly for Fernet
            raw_key = hashlib.sha256(hash_result.encode()).digest()
            key = base64.urlsafe_b64encode(raw_key)
            
            return salt, key
        except ImportError:
            logger.warning("Argon2 not available, falling back to PBKDF2")
    
    # Fall back to PBKDF2 if Argon2 not available or not enabled
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=app.config['PBKDF2_ITERATIONS'],
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return salt, key

# Function to generate or load encryption key
def load_key(key_id=None, password=None, key_name=None, expiry_days=None):
    try:
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
                is_password_protected = True
            else:
                # Generate random key
                key = Fernet.generate_key()
                is_password_protected = False
                
            # Store key ID for reference
            key_path = os.path.join(KEY_FOLDER, f"{key_id}.key")
            with open(key_path, "wb") as key_file:
                key_file.write(key)
            
            # Calculate expiry date if provided
            expires_at = None
            if expiry_days:
                expires_at = (datetime.now() + timedelta(days=expiry_days)).isoformat()
            
            # Store key metadata in database
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                INSERT INTO keys (id, created_at, expires_at, is_password_protected, name, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (key_id, datetime.now().isoformat(), expires_at, is_password_protected, key_name or f"Key-{key_id[:8]}", "{}"))
                conn.commit()
            
            logger.info(f"Generated new key with ID: {key_id}")
        else:
            # Check if key has expired
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT expires_at, is_password_protected FROM keys WHERE id = ?', (key_id,))
                result = cursor.fetchone()
                
                if not result:
                    logger.error(f"Key not found in database: {key_id}")
                    return key_id, None
                
                expires_at, is_password_protected = result
                
                if expires_at and datetime.fromisoformat(expires_at) < datetime.now():
                    logger.error(f"Key expired: {key_id}")
                    return key_id, None
            
            # Load existing key
            key_path = os.path.join(KEY_FOLDER, f"{key_id}.key")
            salt_path = os.path.join(KEY_FOLDER, f"{key_id}.salt")
            
            if not os.path.exists(key_path):
                logger.error(f"Key file not found: {key_id}")
                return key_id, None
                
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
    except Exception as e:
        logger.error(f"Error in load_key: {str(e)}")
        return key_id if key_id else str(uuid.uuid4()), None

# Enhanced encryption with authentication
def encrypt_file_with_auth(cipher, file_data):
    # Encrypt the data
    encrypted_data = cipher.encrypt(file_data)
    
    # Add HMAC for authentication
    secret_key = app.secret_key.encode()
    h = hmac.new(secret_key, encrypted_data, hashlib.sha256)
    hmac_digest = h.digest()
    
    # Combine HMAC and encrypted data
    return hmac_digest + encrypted_data

# Decrypt with authentication
def decrypt_file_with_auth(cipher, encrypted_data_with_hmac):
    # Extract HMAC and encrypted data
    hmac_digest = encrypted_data_with_hmac[:32]  # SHA-256 is 32 bytes
    encrypted_data = encrypted_data_with_hmac[32:]
    
    # Verify HMAC
    secret_key = app.secret_key.encode()
    h = hmac.new(secret_key, encrypted_data, hashlib.sha256)
    calculated_hmac = h.digest()
    
    if not hmac.compare_digest(hmac_digest, calculated_hmac):
        raise ValueError("HMAC verification failed - data may have been tampered with")
    
    # Decrypt the data
    return cipher.decrypt(encrypted_data)

# Function to encrypt file in chunks
def encrypt_file_chunked(cipher, input_stream, output_stream, callback=None):
    total_size = 0
    chunk_size = app.config['ENCRYPTION_CHUNK_SIZE']
    
    while True:
        chunk = input_stream.read(chunk_size)
        if not chunk:
            break
            
        # Encrypt this chunk
        encrypted_chunk = cipher.encrypt(chunk)
        output_stream.write(encrypted_chunk)
        
        total_size += len(chunk)
        if callback:
            callback(total_size)
    
    return total_size

# Function to decrypt file in chunks
def decrypt_file_chunked(cipher, input_stream, output_stream, callback=None):
    total_size = 0
    chunk_size = app.config['ENCRYPTION_CHUNK_SIZE']
    
    while True:
        # For Fernet, we need to read full messages
        # This is a simplified approach - in production would need to handle message boundaries
        try:
            chunk = input_stream.read(chunk_size)
            if not chunk:
                break
                
            # Decrypt this chunk
            decrypted_chunk = cipher.decrypt(chunk)
            output_stream.write(decrypted_chunk)
            
            total_size += len(decrypted_chunk)
            if callback:
                callback(total_size)
        except Exception as e:
            logger.error(f"Error decrypting chunk: {str(e)}")
            raise
    
    return total_size

# ================ Routes ================
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

@app.route('/dashboard')
def dashboard():
    # Get statistics for the dashboard
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get recent files
        cursor.execute('''
        SELECT f.id, f.original_filename, f.encrypted_filename, f.size_bytes, f.created_at, k.name as key_name
        FROM files f
        JOIN keys k ON f.key_id = k.id
        ORDER BY f.created_at DESC LIMIT 10
        ''')
        recent_files = cursor.fetchall()
        
        # Get active keys
        cursor.execute('''
        SELECT id, name, created_at, expires_at, is_password_protected
        FROM keys
        WHERE expires_at IS NULL OR expires_at > datetime('now')
        ORDER BY created_at DESC LIMIT 10
        ''')
        active_keys = cursor.fetchall()
        
        # Get statistics
        cursor.execute('SELECT COUNT(*) as count FROM files')
        total_files = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM keys')
        total_keys = cursor.fetchone()['count']
        
        cursor.execute('SELECT SUM(size_bytes) as total FROM files')
        result = cursor.fetchone()
        total_size = result['total'] if result['total'] is not None else 0
        
    return render_template(
        "dashboard.html",
        recent_files=recent_files,
        active_keys=active_keys,
        total_files=total_files,
        total_keys=total_keys,
        total_size=total_size
    )

# File upload and encryption
@app.route('/upload', methods=['POST'])
@csrf_protected
@rate_limit
def upload_file():
    try:
        if 'file' not in request.files:
            flash("No file selected!", "error")
            return redirect(url_for('encrypt_page'))
        
        file = request.files['file']
        if file.filename == '':
            flash("No selected file!", "error")
            return redirect(url_for('encrypt_page'))
        
        # Get password if provided
        password = request.form.get('password', '')
        key_name = request.form.get('key_name', '')
        expiry_days = request.form.get('expiry_days')
        if expiry_days:
            try:
                expiry_days = int(expiry_days)
            except ValueError:
                expiry_days = None
        
        # Get notification email if provided
        notification_email = request.form.get('email', '')
        
        # Generate secure filename
        filename = secure_filename(file.filename)
        
        # For batch upload (multiple files)
        if hasattr(file, 'getlist') and len(file.getlist()) > 1:
            # Handle multiple files (zip them first)
            files = file.getlist()
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for f in files:
                    zip_file.writestr(secure_filename(f.filename), f.read())
            
            file_data = zip_buffer.getvalue()
            filename = "batch_upload.zip"
        else:
            # Read file data for single file
            file_data = file.read()
        
        # Generate key and encrypt data
        key_id, cipher = load_key(password=password if password else None, key_name=key_name, expiry_days=expiry_days)
        
        if cipher is None:
            flash("Error generating encryption key!", "error")
            return redirect(url_for('encrypt_page'))
        
        # Generate file ID
        file_id = str(uuid.uuid4())
        
        # Save encrypted file
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        encrypted_filename = f"{timestamp}_{filename}.enc"
        encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)
        
        # Stream-based encryption for large files
        with open(encrypted_path, "wb") as enc_file:
            input_stream = BytesIO(file_data)
            encrypt_file_chunked(cipher, input_stream, enc_file)
        
        # Store file metadata in database
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO files (id, original_filename, encrypted_filename, key_id, size_bytes, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (file_id, filename, encrypted_filename, key_id, len(file_data), 
                  datetime.now().isoformat(), json.dumps({
                      "user_agent": request.user_agent.string,
                      "ip_address": request.remote_addr
                  })))
            conn.commit()
        
        # Store the key ID in session
        session['last_key_id'] = key_id
        session['last_filename'] = encrypted_filename
        session['last_file_id'] = file_id
        
        # Log this action
        log_access("encrypt", file_id=file_id, key_id=key_id)
        
        # Send notification if email provided
        if notification_email and app.config['ENABLE_EMAIL']:
            send_email_notification(
                notification_email,
                "File Encrypted Successfully",
                f"Your file '{filename}' has been encrypted.\n\n"
                f"Key ID: {key_id}\n"
                f"Please keep this key ID safe as you will need it to decrypt your file."
            )
        
        # Track file size
        file_size = len(file_data) / 1024  # Size in KB
        
        logger.info(f"Encrypted file: {filename} -> {encrypted_filename} ({file_size:.2f} KB)")
        flash(f"File encrypted successfully!", "success")
        
        return render_template("download.html", 
                              filename=encrypted_filename,
                              file_id=file_id,
                              key_id=key_id, 
                              original_filename=filename,
                              is_password_protected=bool(password))
    except Exception as e:
        logger.error(f"Error in upload_file: {str(e)}")
        flash(f"Error encrypting file: {str(e)}", "error")
        return redirect(url_for('encrypt_page'))

# File decryption and download
@app.route('/decrypt-file', methods=['POST'])
@csrf_protected
@rate_limit
def decrypt_file():
    try:
        # Get the key ID and password if provided
        key_id = request.form.get("key_id")
        password = request.form.get("password", "")
        notification_email = request.form.get("email", "")
        
        if not key_id:
            flash("No key ID provided!", "error")
            return redirect(url_for('decrypt_page'))
        
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
            log_access("decrypt_attempt", key_id=key_id, success=False)
            flash("Invalid decryption key or password!", "error")
            return redirect(url_for('decrypt_page'))
        
        try:
            # For stream-based decryption
            input_stream = BytesIO(encrypted_data)
            output_stream = BytesIO()
            
            try:
                decrypt_file_chunked(cipher, input_stream, output_stream)
                decrypted_data = output_stream.getvalue()
            except Exception as e:
                logger.error(f"Chunked decryption failed: {str(e)}")
                # Try regular decryption as fallback
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
            
            # Log successful decryption
            log_access("decrypt", key_id=key_id, success=True)
            
            # Send notification if email provided
            if notification_email and app.config['ENABLE_EMAIL']:
                send_email_notification(
                    notification_email,
                    "File Decrypted Successfully",
                    f"Your file '{original_filename}' has been decrypted successfully."
                )
            
            file_size = len(decrypted_data) / 1024  # Size in KB
            logger.info(f"Decrypted file: {file.filename} -> {original_filename} ({file_size:.2f} KB)")
            return send_file(temp_path, as_attachment=True, download_name=original_filename)
        
        except Exception as e:
            log_access("decrypt_error", key_id=key_id, success=False)
            logger.error(f"Decryption error: {str(e)}")
            flash("Decryption failed! Invalid key/password or corrupted file.", "error")
            return redirect(url_for('decrypt_page'))
    except Exception as e:
        logger.error(f"Error in decrypt_file: {str(e)}")
        flash(f"Error decrypting file: {str(e)}", "error")
        return redirect(url_for('decrypt_page'))

# Download encrypted file
@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        flash("File not found!", "error")
        return redirect(url_for('encrypt_page'))
    return send_file(file_path, as_attachment=True)

# Generate QR code for key sharing (continued)
@app.route('/key-qr/<key_id>')
@rate_limit
def key_qr(key_id):
    try:
        # Check if key exists
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM keys WHERE id = ?', (key_id,))
            if not cursor.fetchone():
                flash("Key not found!", "error")
                return redirect(url_for('index'))
        
        # Generate URL for key sharing
        share_url = urljoin(app.config['BASE_URL'], f"/shared-key/{key_id}")
        
        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(share_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save QR code to BytesIO
        img_io = io.BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        
        log_access("qr_code_generated", key_id=key_id)
        
        # Return QR code image
        return send_file(img_io, mimetype='image/png')
    except Exception as e:
        logger.error(f"Error generating QR code: {str(e)}")
        flash("Error generating QR code", "error")
        return redirect(url_for('index'))

# Create a time-limited sharing link for a key
@app.route('/create-share/<key_id>', methods=['POST'])
@csrf_protected
@rate_limit
def create_share(key_id):
    try:
        # Validate key exists
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM keys WHERE id = ?', (key_id,))
            if not cursor.fetchone():
                flash("Key not found!", "error")
                return redirect(url_for('index'))
        
        # Get share duration and max accesses
        hours = int(request.form.get('hours', 24))
        max_access = int(request.form.get('max_access', 3))
        
        # Generate share ID and expiry time
        share_id = str(uuid.uuid4())
        expires_at = (datetime.now() + timedelta(hours=hours)).isoformat()
        
        # Store in database
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO shared_keys (share_id, key_id, expires_at, max_access)
            VALUES (?, ?, ?, ?)
            ''', (share_id, key_id, expires_at, max_access))
            conn.commit()
        
        # Generate share URL
        share_url = urljoin(app.config['BASE_URL'], f"/shared-key/{share_id}")
        
        log_access("share_created", key_id=key_id)
        
        return render_template("share.html", share_url=share_url, expires_at=expires_at, max_access=max_access)
    except Exception as e:
        logger.error(f"Error creating share: {str(e)}")
        flash(f"Error creating share: {str(e)}", "error")
        return redirect(url_for('index'))

# Access a shared key
@app.route('/shared-key/<share_id>')
@rate_limit
def shared_key(share_id):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
            SELECT key_id, expires_at, access_count, max_access 
            FROM shared_keys 
            WHERE share_id = ?
            ''', (share_id,))
            share = cursor.fetchone()
            
            if not share:
                flash("Shared key not found or has expired", "error")
                return redirect(url_for('index'))
            
            # Check if expired
            if datetime.fromisoformat(share['expires_at']) < datetime.now():
                flash("This shared key has expired", "error")
                return redirect(url_for('index'))
            
            # Check access count
            if share['access_count'] >= share['max_access']:
                flash("Maximum access count reached for this shared key", "error")
                return redirect(url_for('index'))
            
            # Increment access count
            cursor.execute('''
            UPDATE shared_keys 
            SET access_count = access_count + 1 
            WHERE share_id = ?
            ''', (share_id,))
            conn.commit()
            
            # Get key details
            cursor.execute('SELECT name FROM keys WHERE id = ?', (share['key_id'],))
            key = cursor.fetchone()
            
        log_access("shared_key_accessed", key_id=share['key_id'])
        
        return render_template("shared_key.html", 
                              key_id=share['key_id'], 
                              key_name=key['name'], 
                              expires=share['expires_at'],
                              remaining_uses=share['max_access'] - share['access_count'])
    except Exception as e:
        logger.error(f"Error accessing shared key: {str(e)}")
        flash("Error accessing shared key", "error")
        return redirect(url_for('index'))

# Directory encryption
@app.route('/encrypt-directory', methods=['POST'])
@csrf_protected
@rate_limit
def encrypt_directory():
    try:
        if 'directory' not in request.files:
            flash("No directory selected!", "error")
            return redirect(url_for('encrypt_page'))
        
        files = request.files.getlist('directory')
        if not files or len(files) == 0:
            flash("No files found in directory!", "error")
            return redirect(url_for('encrypt_page'))
        
        # Get password if provided
        password = request.form.get('password', '')
        key_name = request.form.get('key_name', 'Directory Key')
        
        # Generate key for encryption
        key_id, cipher = load_key(password=password if password else None, key_name=key_name)
        
        if cipher is None:
            flash("Error generating encryption key!", "error")
            return redirect(url_for('encrypt_page'))
        
        # Create a zip archive of the encrypted files
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        zip_filename = f"encrypted_directory_{timestamp}.zip"
        zip_path = os.path.join(UPLOAD_FOLDER, zip_filename)
        
        total_size = 0
        file_count = 0
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in files:
                if file.filename == '':
                    continue
                
                # Read and encrypt each file
                file_data = file.read()
                encrypted_data = cipher.encrypt(file_data)
                
                # Add to zip with original path structure
                filename = secure_filename(file.filename)
                zipf.writestr(f"{filename}.enc", encrypted_data)
                
                total_size += len(file_data)
                file_count += 1
        
        # Store metadata in database
        file_id = str(uuid.uuid4())
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO files (id, original_filename, encrypted_filename, key_id, size_bytes, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (file_id, "directory_archive", zip_filename, key_id, total_size, 
                  datetime.now().isoformat(), json.dumps({
                      "file_count": file_count,
                      "user_agent": request.user_agent.string,
                      "ip_address": request.remote_addr
                  })))
            conn.commit()
        
        log_access("encrypt_directory", file_id=file_id, key_id=key_id)
        
        flash(f"Directory encrypted successfully with {file_count} files!", "success")
        return render_template("download.html", 
                              filename=zip_filename,
                              file_id=file_id, 
                              key_id=key_id,
                              original_filename="directory_archive",
                              is_password_protected=bool(password),
                              file_count=file_count)
    except Exception as e:
        logger.error(f"Error encrypting directory: {str(e)}")
        flash(f"Error encrypting directory: {str(e)}", "error")
        return redirect(url_for('encrypt_page'))

# Split key using Shamir's Secret Sharing
@app.route('/split-key/<key_id>', methods=['POST'])
@csrf_protected
@rate_limit
def split_key(key_id):
    try:
        # Check if the key exists
        key_path = os.path.join(KEY_FOLDER, f"{key_id}.key")
        if not os.path.exists(key_path):
            flash("Key not found!", "error")
            return redirect(url_for('index'))
        
        # Get parameters for splitting
        shares = int(request.form.get('shares', 3))
        threshold = int(request.form.get('threshold', 2))
        
        if shares < threshold:
            flash("Number of shares must be greater than or equal to threshold", "error")
            return redirect(url_for('index'))
        
        # Implement Shamir's Secret Sharing
        try:
            import secrets
            import hashlib
            from decimal import Decimal, getcontext
            
            # Read the key
            with open(key_path, "rb") as key_file:
                key_data = key_file.read()
            
            # Convert key to integer for sharing
            key_int = int.from_bytes(key_data, byteorder='big')
            
            # Set precision for decimal calculations
            getcontext().prec = 128
            
            # Generate random polynomial coefficients
            prime = 2**256 - 189  # A prime number larger than our key
            coefficients = [key_int]  # First coefficient is the secret
            for i in range(threshold - 1):
                coefficients.append(secrets.randbelow(prime))
            
            # Generate shares
            key_shares = []
            for i in range(1, shares + 1):
                x = i
                y = 0
                for j, coeff in enumerate(coefficients):
                    y = (y + coeff * pow(x, j, prime)) % prime
                key_shares.append((x, y))
            
            # Store shares in database or return to user
            share_data = []
            for i, (x, y) in enumerate(key_shares):
                share_id = str(uuid.uuid4())
                share_info = {
                    'id': share_id,
                    'x': x,
                    'y': y,
                    'threshold': threshold,
                    'total_shares': shares,
                    'key_id': key_id
                }
                share_data.append(share_info)
            
            log_access("key_split", key_id=key_id)
            
            return render_template("key_shares.html", shares=share_data, threshold=threshold, key_id=key_id)
        except ImportError:
            flash("Required libraries for key splitting not available", "error")
            return redirect(url_for('index'))
            
    except Exception as e:
        logger.error(f"Error splitting key: {str(e)}")
        flash(f"Error splitting key: {str(e)}", "error")
        return redirect(url_for('index'))

# Reconstruct key from shares
@app.route('/reconstruct-key', methods=['POST'])
@csrf_protected
@rate_limit
def reconstruct_key():
    try:
        # Get shares from form
        shares_json = request.form.get('shares', '[]')
        shares = json.loads(shares_json)
        
        if not shares or len(shares) < 2:
            flash("Not enough shares provided", "error")
            return redirect(url_for('decrypt_page'))
        
        # Parse shares
        x_values = []
        y_values = []
        key_id = None
        threshold = 0
        
        for share in shares:
            x_values.append(int(share['x']))
            y_values.append(int(share['y']))
            if key_id is None:
                key_id = share['key_id']
            threshold = max(threshold, int(share['threshold']))
        
        if len(x_values) < threshold:
            flash(f"Need at least {threshold} shares to reconstruct the key", "error")
            return redirect(url_for('decrypt_page'))
        
        # Implement Lagrange interpolation for reconstruction
        try:
            from decimal import Decimal, getcontext
            
            # Set precision for decimal calculations
            getcontext().prec = 128
            
            prime = 2**256 - 189  # Same prime as used for splitting
            
            # Lagrange interpolation
            secret = 0
            for i in range(len(x_values)):
                numerator = 1
                denominator = 1
                for j in range(len(x_values)):
                    if i != j:
                        numerator = (numerator * (-x_values[j])) % prime
                        denominator = (denominator * (x_values[i] - x_values[j])) % prime
                
                # Calculate the modular multiplicative inverse of denominator
                inv_denominator = pow(denominator, prime - 2, prime)  # Fermat's little theorem
                
                lagrange_poly = (y_values[i] * numerator * inv_denominator) % prime
                secret = (secret + lagrange_poly) % prime
            
            # Convert back to bytes
            secret_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, byteorder='big')
            
            # Ensure it's a valid Fernet key (32 bytes base64-encoded)
            if len(secret_bytes) != 32:
                # Hash it to get a consistent length
                secret_bytes = hashlib.sha256(secret_bytes).digest()
            
            key = base64.urlsafe_b64encode(secret_bytes)
            
            # Create temporary key file
            temp_id = str(uuid.uuid4())
            temp_dir = os.path.join(TEMP_FOLDER, temp_id)
            os.makedirs(temp_dir, exist_ok=True)
            
            temp_key_path = os.path.join(temp_dir, f"{key_id}.key")
            with open(temp_key_path, "wb") as key_file:
                key_file.write(key)
            
            log_access("key_reconstructed", key_id=key_id)
            
            flash("Key reconstructed successfully! You can now use it for decryption.", "success")
            return render_template("reconstructed_key.html", key_id=key_id, temp_path=temp_key_path)
        except Exception as e:
            logger.error(f"Error in key reconstruction algorithm: {str(e)}")
            flash(f"Error reconstructing key: {str(e)}", "error")
            return redirect(url_for('decrypt_page'))
    except Exception as e:
        logger.error(f"Error reconstructing key: {str(e)}")
        flash(f"Error reconstructing key: {str(e)}", "error")
        return redirect(url_for('decrypt_page'))

# Key rotation
@app.route('/rotate-key/<key_id>', methods=['POST'])
@csrf_protected
@rate_limit
def rotate_key(key_id):
    try:
        # Check if the key exists
        key_path = os.path.join(KEY_FOLDER, f"{key_id}.key")
        if not os.path.exists(key_path):
            flash("Key not found!", "error")
            return redirect(url_for('index'))
        
        # Get optional password
        password = request.form.get('password', '')
        key_name = request.form.get('key_name', f"Rotated-{key_id[:8]}")
        
        # Create new key
        new_key_id, new_cipher = load_key(password=password if password else None, key_name=key_name)
        
        if new_cipher is None:
            flash("Error generating new key!", "error")
            return redirect(url_for('index'))
        
        # Find all files encrypted with the old key
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT id, encrypted_filename FROM files WHERE key_id = ?', (key_id,))
            files = cursor.fetchall()
            
            # Load old key
            old_salt_path = os.path.join(KEY_FOLDER, f"{key_id}.salt")
            old_is_password_protected = os.path.exists(old_salt_path)
            
            old_key_id, old_cipher = load_key(key_id, request.form.get('old_password', '') if old_is_password_protected else None)
            
            if old_cipher is None:
                flash("Error loading old key for rotation!", "error")
                return redirect(url_for('index'))
            
            # Re-encrypt each file with the new key
            for file in files:
                file_path = os.path.join(UPLOAD_FOLDER, file['encrypted_filename'])
                if not os.path.exists(file_path):
                    continue
                
                try:
                    # Read encrypted file
                    with open(file_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    # Decrypt with old key
                    decrypted_data = old_cipher.decrypt(encrypted_data)
                    
                    # Re-encrypt with new key
                    new_encrypted_data = new_cipher.encrypt(decrypted_data)
                    
                    # Save with new encryption
                    with open(file_path, 'wb') as f:
                        f.write(new_encrypted_data)
                    
                    # Update database
                    cursor.execute('UPDATE files SET key_id = ? WHERE id = ?', (new_key_id, file['id']))
                except Exception as e:
                    logger.error(f"Error rotating key for file {file['id']}: {str(e)}")
            
            # Mark old key as rotated
            cursor.execute('''
            UPDATE keys 
            SET metadata = json_set(COALESCE(metadata, '{}'), '$.rotated', json('{"to": "' || ? || '", "date": "' || ? || '"}'))
            WHERE id = ?
            ''', (new_key_id, datetime.now().isoformat(), key_id))
            
            conn.commit()
        
        log_access("key_rotated", key_id=key_id)
        
        flash(f"Key rotated successfully! {len(files)} files updated.", "success")
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"Error rotating key: {str(e)}")
        flash(f"Error rotating key: {str(e)}", "error")
        return redirect(url_for('index'))

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

@app.errorhandler(429)
def too_many_requests(error):
    return render_template("rate_limit.html"), 429

# ================ Utility Functions ================
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
        try:
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
            
            # Also clean up expired shared keys
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                DELETE FROM shared_keys 
                WHERE expires_at < datetime('now') OR access_count >= max_access
                ''')
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error in background cleanup: {str(e)}")
                            
        # Sleep for 1 hour before next check
        time.sleep(3600)

# API endpoints for status monitoring
@app.route('/api/status')
@rate_limit
def api_status():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            
            # Get system statistics
            cursor.execute('SELECT COUNT(*) as count FROM files')
            total_files = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) as count FROM keys')
            total_keys = cursor.fetchone()[0]
            
            cursor.execute('SELECT SUM(size_bytes) as total FROM files')
            total_size = cursor.fetchone()[0] or 0
            
            # Get recent activity
            cursor.execute('''
            SELECT action, COUNT(*) as count 
            FROM access_logs 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY action
            ''')
            activities = {row[0]: row[1] for row in cursor.fetchall()}
            
        return jsonify({
            "status": "healthy",
            "version": "1.2.0",
            "statistics": {
                "total_files": total_files,
                "total_keys": total_keys,
                "total_size_bytes": total_size
            },
            "recent_activity": activities
        })
    except Exception as e:
        logger.error(f"Error in status API: {str(e)}")
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

# Add streaming file upload for large files
@app.route('/stream-upload', methods=['POST'])
@csrf_protected
@rate_limit
def stream_upload():
    # This endpoint handles chunked file uploads
    chunk = request.files.get('chunk')
    chunk_number = int(request.form.get('chunk_number', 0))
    total_chunks = int(request.form.get('total_chunks', 1))
    filename = request.form.get('filename', '')
    upload_id = request.form.get('upload_id', str(uuid.uuid4()))
    
    if not chunk:
        return jsonify({"error": "No chunk provided"}), 400
    
    # Create directory for chunked upload
    upload_dir = os.path.join(TEMP_FOLDER, f"upload_{upload_id}")
    os.makedirs(upload_dir, exist_ok=True)
    
    # Save this chunk
    chunk_path = os.path.join(upload_dir, f"chunk_{chunk_number}")
    chunk.save(chunk_path)
    
    # Check if all chunks are uploaded
    if chunk_number == total_chunks - 1:
        # All chunks received, combine them
        output_path = os.path.join(upload_dir, secure_filename(filename))
        with open(output_path, 'wb') as outfile:
            for i in range(total_chunks):
                chunk_file = os.path.join(upload_dir, f"chunk_{i}")
                if not os.path.exists(chunk_file):
                    return jsonify({"error": f"Missing chunk {i}"}), 400
                
                with open(chunk_file, 'rb') as infile:
                    outfile.write(infile.read())
        
        # Cleanup chunk files
        for i in range(total_chunks):
            chunk_file = os.path.join(upload_dir, f"chunk_{i}")
            try:
                os.remove(chunk_file)
            except:
                pass
        
        # Return path to the combined file
        return jsonify({
            "status": "complete",
            "temp_path": output_path
        })
    else:
        # More chunks expected
        return jsonify({
            "status": "chunk_received",
            "chunk_number": chunk_number,
            "upload_id": upload_id
        })

if __name__ == '__main__':
    # Start background cleanup thread
    cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
    cleanup_thread.start()
    
    # Use gunicorn or waitress for production
    if os.environ.get('ENV') == 'production':
        try:
            from waitress import serve
            serve(app, host='0.0.0.0', port=int(os.environ.get('PORT', 7500)))
        except ImportError:
            app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 7500)))
    else:
        app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 7500)))