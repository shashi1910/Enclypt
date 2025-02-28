# Project Enclypt

## Overview

This is a Flask-based web application that allows users to securely encrypt and decrypt files using the **Fernet** symmetric encryption algorithm. The app provides an intuitive web interface for file uploads, encryption, decryption, and secure downloads.

## Features

- **File Encryption**: Upload a file and encrypt it using a unique key.
- **File Decryption**: Upload an encrypted file and decrypt it using the correct key.
- **Automatic Key Generation & Storage**: Generates a new key for each encryption and securely stores it.
- **Secure File Handling**: Uses secure filenames and enforces size restrictions (max 16MB).
- **Error Handling**: Provides user-friendly error messages for invalid operations.
- **Logging**: Maintains logs of encryption and decryption activities.

## Installation

### Prerequisites

Ensure you have the following installed:

- Python 3.7+
- pip (Python package manager)

### Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/Enclypt.git
   cd Enclypt
   ```
2. **Create a Virtual Environment (Recommended)**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Set Up Environment Variables**:
   Create a `.env` file and define:
   ```
   SECRET_KEY=your_random_secret_key
   PORT=7500  # Optional, defaults to 7500
   ```
5. **Run the Application**:
   ```bash
   python app.py
   ```
6. Open your browser and navigate to:
   ```
   http://127.0.0.1:7500
   ```

## Usage

### Encrypt a File

1. Navigate to the **Encrypt** page.
2. Upload a file (max 16MB).
3. The app generates an encrypted file and provides a unique key.
4. Download the encrypted file and securely save the key.

### Decrypt a File

1. Navigate to the **Decrypt** page.
2. Upload the encrypted file.
3. Enter the correct key.
4. Download the decrypted file.

## File Storage Structure

```
flask-encryptor/
│── app.py  # Main Flask application
│── requirements.txt  # Dependencies
│── templates/  # HTML templates
│── static/  # Static files (CSS, JS)
│── uploads/  # Stores encrypted/decrypted files
│── keys/  # Stores encryption keys
│── logs/  # Stores logs
```

## Security Considerations

- **Key Management**: Keys are stored in the `keys/` folder. Users must securely store their key ID to decrypt files.
- **Size Restrictions**: Files larger than 16MB are not allowed to prevent DoS attacks.
- **Logging**: Logs are maintained for security monitoring.

## Future Improvements

- Implement scheduled cleanup for temporary files.
- Add user authentication for secure file handling.
- Use a database for better key management.

## License

This project is licensed under the MIT License.



