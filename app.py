from flask import Flask, request, send_file, render_template, redirect, url_for, flash, session
import os
from cryptography.fernet import Fernet
import uuid
from werkzeug.utils import secure_filename
import logging
from datetime import datetime

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
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB

# Configuration
UPLOAD_FOLDER = "uploads"
KEY_FOLDER = "keys"
for folder in [UPLOAD_FOLDER, KEY_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Function to generate or load encryption key
def load_key(key_id=None):
    if key_id is None:
        # Generate a new key
        key_id = str(uuid.uuid4())
        key = Fernet.generate_key()
        key_path = os.path.join(KEY_FOLDER, f"{key_id}.key")
        with open(key_path, "wb") as key_file:
            key_file.write(key)
        logger.info(f"Generated new key with ID: {key_id}")
    else:
        # Load existing key
        key_path = os.path.join(KEY_FOLDER, f"{key_id}.key")
        if not os.path.exists(key_path):
            logger.error(f"Key not found: {key_id}")
            return None, None
        with open(key_path, "rb") as key_file:
            key = key_file.read()
        logger.info(f"Loaded key with ID: {key_id}")
    
    return key_id, Fernet(key)

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
    
    # Generate secure filename
    filename = secure_filename(file.filename)
    
    # Read file data
    file_data = file.read()
    
    # Generate key and encrypt data
    key_id, cipher = load_key()
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
    
    logger.info(f"Encrypted file: {filename} -> {encrypted_filename}")
    flash(f"File encrypted successfully!", "success")
    return render_template("download.html", 
                          filename=encrypted_filename, 
                          key_id=key_id, 
                          original_filename=filename)

# File decryption and download
@app.route('/decrypt-file', methods=['POST'])
def decrypt_file():
    # Get the key ID and encrypted file
    key_id = request.form.get("key_id")
    
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
    
    # Load the key and decrypt
    _, cipher = load_key(key_id)
    if cipher is None:
        flash("Invalid decryption key!", "error")
        return redirect(url_for('decrypt_page'))
    
    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Generate decrypted filename
        original_filename = file.filename[:-4]  # Remove .enc
        if '_' in original_filename:
            # Remove timestamp if present
            original_filename = original_filename.split('_', 1)[1]
        
        # Create temporary file for download
        temp_path = os.path.join(UPLOAD_FOLDER, f"dec_{original_filename}")
        with open(temp_path, "wb") as dec_file:
            dec_file.write(decrypted_data)
        
        logger.info(f"Decrypted file: {file.filename} -> {original_filename}")
        return send_file(temp_path, as_attachment=True, download_name=original_filename)
    
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        flash("Decryption failed! Invalid key or corrupted file.", "error")
        return redirect(url_for('decrypt_page'))

# Download encrypted file
@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

@app.errorhandler(413)
def request_entity_too_large(error):
    flash("File too large! Maximum size is 16MB.", "error")
    return redirect(url_for('encrypt_page'))

# Clean up temporary files (called by a scheduler in production)
def cleanup_temp_files():
    # This would be implemented for production to remove old files
    pass

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 7500)))
