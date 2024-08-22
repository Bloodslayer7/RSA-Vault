# RSA-Vault
# Overview
RSA-Vault is a desktop application for secure RSA-based encryption and decryption of text files. Built using Python and Tkinter, the application provides a user-friendly interface for securing text content with RSA encryption. The app supports both encryption and decryption processes, ensuring data confidentiality with customizable key storage options.

# Features
RSA Key Generation: Dynamically generates RSA keys for encryption and decryption.
Password Protection: Secure your RSA keys with a strong password.
File Encryption/Decryption: Encrypt and decrypt text files seamlessly using RSA.
Interactive GUI: Simple and intuitive interface with background image support.
Secure Key Storage: Save encryption keys externally to avoid hardcoding sensitive data.

# How It Works
Login: Start with the secure login system using pre-set credentials.
Select File: Browse and select the text file you want to encrypt or decrypt.
Encrypt/Decrypt: Choose the desired action (encryption or decryption) and enter a password to proceed.
Password Protection: During encryption, set a strong password. For decryption, enter the corresponding password used during encryption.

# Getting Started
Installation - Clone the repository:
git clone https://github.com/Bloodslayer7/RSA-vault.git
cd RSA-vault

# Install the required packages:
pip install -r requirements.txt
Run the application:

python RSA_TOOL.py

# Running the Executable (.exe)  # If you prefer to use the pre-built executable:

Download the .exe file from the releases section (if you just want to run the executable you will have to also download credentials.txt and the backgroundimage.png).
Double-click the .exe file to launch the application without needing Python installed.
(# if you just want to run the executable you will have to also download credentials.txt and the backgroundimage.png)

# How to Use
Login: Enter the username and password as set in the credentials.txt file.
Select a File: Use the "Browse" button to choose a text file.
Encrypt/Decrypt: Click on "Encrypt" to secure your file or "Decrypt" to restore the original content.
Save: The processed content will overwrite the original file.

# Project Structure
RSA-vault/
│
├── main.py             # Main application file
├── rsa_keys.txt        # Placeholder for RSA keys (dynamically generated)
├── credentials.txt     # Login credentials file
├── requirements.txt    # Dependencies
├── README.md           # Project documentation
└── background.png      # Background image for the GUI

# Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue if you have any suggestions or improvements.
