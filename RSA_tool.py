import re
import tkinter as tk
import sys
from tkinter import filedialog, messagebox, simpledialog, Toplevel, Label, Entry, Button
from PIL import Image, ImageTk
import random
from math import gcd
from sympy import primerange
import os

# Generate a prime number with a specific number of digits
def generate_prime(digits):
    return random.choice(list(primerange(10 ** (digits - 1), 10 ** digits)))

# RSA encryption function
def rsa_encryption(message, e, n):
    encrypted_message = [str(pow(ord(char), e, n)) for char in message]
    encrypted_string = ' '.join(encrypted_message)
    return encrypted_string

# RSA decryption function
def rsa_decryption(encrypted_message, d, n):
    decrypted_message = ''.join([chr(pow(int(char), d, n)) for char in encrypted_message.split()])
    return decrypted_message

# Save the keys externally in a file
def save_keys(password, p, q, e, d, n, phi_n, key_file='rsa_keys.txt'):
    # Save the keys and password for later use in an external file
    with open(key_file, 'w') as kf:
        kf.write(f"{password} {p} {q} {e} {d} {n} {phi_n}")

# Main RSA function to generate keys and process the content
def rsa(message_content, operation, password, key_file='rsa_keys.txt'):
    if operation == 'decrypt':
        if not os.path.exists(key_file):
            raise FileNotFoundError(f"Key file '{key_file}' not found.")
        with open(key_file, 'r') as kf:
            keys = kf.read().split()
            stored_password = keys[0]
            if stored_password != password:
                raise ValueError("Incorrect password")
            p = int(keys[1])
            q = int(keys[2])
            e = int(keys[3])
            d = int(keys[4])
            n = int(keys[5])
            phi_n = int(keys[6])
        return rsa_decryption(message_content, d, n)
    else:
        # Convert the message to a list of ASCII values
        ascii_values = [ord(char) for char in message_content]
        digits = len(str(max(ascii_values)))

        # Generate two random prime numbers p and q
        p = generate_prime(digits)
        while True:
            q = generate_prime(digits)
            if gcd(p, q) == 1 and p != q:
                break

        # Calculate n = p * q
        n = p * q

        # Calculate phi_n = (p-1) * (q-1)
        phi_n = (p - 1) * (q - 1)

        # Generate a list of prime numbers less than phi_n
        primes = list(primerange(1, phi_n))

        # Select a random prime number that is relatively prime to phi_n
        e = random.choice(primes)
        while gcd(e, phi_n) != 1:
            e = random.choice(primes)

        # Calculate d = e^-1 mod phi_n
        d = pow(e, -1, phi_n)

        # Save the keys externally instead of embedding them in the executable
        save_keys(password, p, q, e, d, n, phi_n, key_file=key_file)

        return rsa_encryption(message_content, e, n)

class PasswordDialog:
    def __init__(self, parent):
        self.top = Toplevel(parent)
        self.top.title("Set Password")
        self.top.geometry("300x300")

        self.label = Label(self.top, text="Enter your password:")
        self.label.pack(pady=10)

        self.entry_password = Entry(self.top, show='*')
        self.entry_password.pack(pady=5)
        self.entry_password.bind('<KeyRelease>', self.check_password)

        # Password condition labels
        self.label_length = Label(self.top, text="At least 8 characters")
        self.label_length.pack()

        self.label_upper = Label(self.top, text="At least one uppercase letter")
        self.label_upper.pack()

        self.label_lower = Label(self.top, text="At least one lowercase letter")
        self.label_lower.pack()

        self.label_digit = Label(self.top, text="At least one digit")
        self.label_digit.pack()

        self.label_special = Label(self.top, text="At least one special character")
        self.label_special.pack()

        self.button = Button(self.top, text="Set Password", command=self.set_password)
        self.button.pack(pady=20)

        self.password = None

    def check_password(self, event=None):
        password = self.entry_password.get()

        # Validate the password
        length_valid = len(password) >= 8
        upper_valid = re.search(r"[A-Z]", password) is not None
        lower_valid = re.search(r"[a-z]", password) is not None
        digit_valid = re.search(r"\d", password) is not None
        special_valid = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is not None

        # Update label colors based on validation
        self.label_length.config(fg='green' if length_valid else 'red')
        self.label_upper.config(fg='green' if upper_valid else 'red')
        self.label_lower.config(fg='green' if lower_valid else 'red')
        self.label_digit.config(fg='green' if digit_valid else 'red')
        self.label_special.config(fg='green' if special_valid else 'red')

        # Enable the button only if all conditions are met
        self.button.config(state=tk.NORMAL
        if all([length_valid, upper_valid, lower_valid, digit_valid, special_valid])
        else tk.DISABLED)

    def set_password(self):
        self.password = self.entry_password.get()
        self.top.destroy()

# Function to get the correct path for bundled files in a PyInstaller .exe
def get_resource_path(relative_path):
    try:
        # If the program is running as a PyInstaller bundle, find the temp directory.
        base_path = sys._MEIPASS
    except AttributeError:
        # If running in a normal Python environment, use the current directory.
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")
        self.root.geometry("300x200")

        self.label_username = tk.Label(root, text="Username:")
        self.label_username.pack(pady=10)
        self.entry_username = tk.Entry(root)
        self.entry_username.pack(pady=5)

        self.label_password = tk.Label(root, text="Password:")
        self.label_password.pack(pady=10)
        self.entry_password = tk.Entry(root, show='*')
        self.entry_password.pack(pady=5)

        self.login_button = tk.Button(root, text="Login", command=self.check_credentials)
        self.login_button.pack(pady=20)

    def check_credentials(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        # Get the correct path for the embedded credentials.txt file
        credentials_path = get_resource_path('credentials.txt')

        if not os.path.exists(credentials_path):
            messagebox.showerror("Error", "credentials.txt file is missing!")
            return

        with open(credentials_path, 'r') as f:
            credentials = [line.strip().split() for line in f]

        if [username, password] in credentials:
            self.root.destroy()  # Close the login window
            self.open_rsa_app()  # Open the RSA app window
        else:
            messagebox.showerror("Error", "Username and password do not match")

    def open_rsa_app(self):
        root_rsa = tk.Tk()
        app = RSAApp(root_rsa)
        root_rsa.bind("<Configure>", app.resize_bg_image)
        root_rsa.mainloop()

class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption/Decryption")
        self.root.geometry("800x600")

        # Load the background image
        self.original_bg_image = Image.open(get_resource_path("background.png"))
        self.bg_image = ImageTk.PhotoImage(self.original_bg_image)

        self.background_label = tk.Label(self.root, image=self.bg_image)
        self.background_label.place(relwidth=1, relheight=1)

        # File selection
        self.label = tk.Label(root, text="Select a text file:", font=('TIMES new roman', 15), width=20, bg='white')
        self.label.place(relx=0.5, rely=0.2, anchor='center')

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file, bg='green', width=15, fg='white')
        self.browse_button.place(relx=0.5, rely=0.3, anchor='center')

        self.encrypt_button = tk.Button(root, text="Encrypt", command=lambda: self.process_file('encrypt'), bg='blue',
                                     width=15, fg='white')
        self.decrypt_button = tk.Button(root, text="Decrypt", command=lambda: self.process_file('decrypt'), bg='red',
                                     width=15, fg='white')

        self.encrypt_button.place(relx=0.4, rely=0.4, anchor='center')
        self.decrypt_button.place(relx=0.6, rely=0.4, anchor='center')

        self.result_label = tk.Label(root, text="", bg='white')
        self.result_label.place(relx=0.5, rely=0.5, anchor='center')

    def browse_file(self):
        self.file_path = tk.filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.file_path:
            self.result_label.config(text=f"Selected file: {os.path.basename(self.file_path)}")

    def process_file(self, action):
        if not hasattr(self, 'file_path') or not self.file_path:
            tk.messagebox.showerror("Error", "No file selected!")
            return

        with open(self.file_path, 'r') as file:
            content = file.read()

        if action == 'encrypt':
            password_dialog = PasswordDialog(self.root)
            self.root.wait_window(password_dialog.top)
            password = password_dialog.password
            if not password:
                return
        else:
            password = tk.simpledialog.askstring("Password", "Enter the password for decryption:", show='*')
            if not password:
                tk.messagebox.showerror("Error", "No password entered!")
                return

        try:
            processed_message = rsa(content, action, password)
        except ValueError as e:
            tk.messagebox.showerror("Error", str(e))
            return

        with open(self.file_path, 'w') as file:
            file.write(processed_message)

        self.result_label.config(text=f"File successfully {action}ed.")

    def resize_bg_image(self, event):
        new_width = event.width
        new_height = event.height
        resized_bg_image = self.original_bg_image.resize((new_width, new_height), Image.LANCZOS)
        self.bg_image = ImageTk.PhotoImage(resized_bg_image)
        self.background_label.config(image=self.bg_image)
        # Keep a reference to avoid garbage collection
        self.background_label.image = self.bg_image

# RSA encryption and decryption functions
# ... (Your existing RSA encryption/decryption functions here) ...

if __name__ == "__main__":
    root = tk.Tk()
    login_app = LoginApp(root)
    root.mainloop()
