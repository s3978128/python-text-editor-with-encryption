import tkinter as tk
from tkinter import messagebox, scrolledtext, Menu, filedialog, simpledialog

# pyDes library for DES encryption and decryption
import pyDes # DES algorithm
from hashlib import sha256 # Use SHA256 hashing algorithm

# pycryptodome library for RSA encryption and decryption
from Crypto.Cipher import PKCS1_OAEP # Use PKCS1_OAEP padding scheme
from Crypto.PublicKey import RSA # RSA algorithm
from Crypto import Random # Random number generator
from Crypto.Random import get_random_bytes # Random bytes generator
from Crypto.Hash import SHA256 # SHA256 hashing algorithm

## Text editor functions
def open_file():
    """Open a file for editing."""
    filepath = tk.filedialog.askopenfilename(
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if not filepath:
        return
    txt_edit.delete("1.0", tk.END)
    with open(filepath, mode="r", encoding="utf-8") as input_file:
        text = input_file.read()
        txt_edit.insert(tk.END, text)
    window.title(f"Text Editor - {filepath}")

def save_file():
    """Save the current file."""
    filepath = tk.filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
    )
    if not filepath:
        return
    with open(filepath, mode="w", encoding="utf-8") as output_file:
        text = txt_edit.get("1.0", tk.END)
        output_file.write(text)
    window.title(f"Text Editor - {filepath}")
    messagebox.showinfo("File Saved", f"File saved as {filepath}")

def about_info():
    """Display information about the application."""
    messagebox.showinfo("About", "A Simple Text Editor with Encryption Algorithms!\nNguyen Viet Ha s3978128\nSecurity for Computing and IT\nEncrypt your .txt files using simplified symmetric (DES) or asymmetric (RSA) encryption algorithms.")

def clear_text():
    """Clear the text editor."""
    txt_edit.delete("1.0", tk.END)

def toggle_dark_mode():
    """Toggle dark mode."""
    bg_color = "white" if window.cget("bg") == "black" else "black"
    fg_color = "white" if bg_color == "black" else "black"
    txt_edit.config(bg=bg_color, fg=fg_color)
    window.config(bg=bg_color)

def update_counts(event=None):
    """Count the number of lines, words, and characters in the text widget."""
    text = txt_edit.get("1.0", tk.END)
    lines = text.count('\n')  # Counting '\n' to find lines
    words = len(text.split())  # Splitting text to count words
    # Count characters by counting all characters except '\n' and ' '
    characters = len(text) - text.count('\n') - text.count(' ') + 1

    lbl_line_count.config(text=f"Lines: {lines}")
    lbl_word_count.config(text=f"Words: {words}")
    lbl_char_count.config(text=f"Characters: {characters}")

# Helper display function
def display_decrypted_content(filepath):
    """ 
    Display decrypted content in text editor when decryption is complete.
    """
    try:
        txt_edit.delete("1.0", tk.END)
        with open(filepath, mode="r", encoding="utf-8") as input_file:
            text = input_file.read()
            txt_edit.insert(tk.END, text)
        window.title(f"Text Editor - {filepath}")
    except UnicodeDecodeError:
        # Handle UnicodeDecodeError when the password is incorrect
        messagebox.showerror("Error", "Decryption failed: Incorrect password!")
    except Exception as e:
        # Handle other errors
        messagebox.showerror("Error", f"Decryption failed: {e}")

## DES encryption and decryption functions
def pad_password(password):
    """
    Pad the password to fit the 8-byte DES key requirement.
    Use a hashing algorithm to generate a fixed-size key.
    """
    # Generate a fixed-size key, using SHA256 hashing algorithm
    hashed_password = sha256(password.encode('utf-8')).digest()  
    return hashed_password[:8]  # Use the first 8 bytes as the key

def encrypt_file_des(filepath, password):
    """ 
    Encrypt a file using DES algorithm.
    Return the encrypted file path if successful.
    """
    try:
        # Read the file to be encrypted
        with open(filepath, 'rb') as file:
            data = file.read()
            
        # Generate a key using the password
        key = pad_password(password)
        
        # Initialize DES object with CBC mode and PKCS5 padding
        # Mode and padding scheme must be the same for encryption and decryption
        # OpenSSL allows more modes and padding schemes
        k = pyDes.des(key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
        
        # Encrypt the data using DES algorithm
        encrypted_data = k.encrypt(data)
        
        # Create a new file path for the encrypted file
        encrypted_filepath = filepath[:-4] + "-des-encrypted.txt"  # Change the file extension
        
        # Write the encrypted data to a new file
        with open(encrypted_filepath, 'wb') as file:
            file.write(encrypted_data)
        
        # Write encrypted data to console
        print(f"Encrypted data: {encrypted_data}")
        
        return encrypted_filepath
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_file_des(filepath, password):
    """
    Decrypt a file using DES algorithm. 
    Return the decrypted file path if successful.
    """
    try:
        # Read the file to be decrypted
        with open(filepath, 'rb') as file:
            encrypted_data = file.read()
        
        # Generate a key using the password
        key = pad_password(password)
        
        # Initialize DES object with CBC mode and PKCS5 padding
        k = pyDes.des(key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
        
        # Decrypt the data using DES algorithm
        decrypted_data = k.decrypt(encrypted_data)
        
        # Create a new file path for the decrypted file
        decrypted_filepath = filepath[:-4] + "-des-decrypted.txt"
        
        # Write the decrypted data to a new file
        with open(decrypted_filepath, 'wb') as file:
            file.write(decrypted_data)
        
        # Write decrypted data to console
        print(f"Decrypted data: {decrypted_data}")
        
        return decrypted_filepath
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Encryption and decryption functions called by the buttons
def encrypt_file_des_with_password():
    """ 
    Encrypt a file using DES algorithm when the user clicks the "Encrypt File" button.
    """
    # Ask user to select a file to encrypt
    filepath = tk.filedialog.askopenfilename(
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if not filepath:
        return

    # Ask user to enter a password for encryption
    password = tk.simpledialog.askstring("Password", "Enter password for encryption:", show='*')
    if password is None:
        # User pressed the "Cancel" button
        return

    # If the password is empty
    if not password:
        messagebox.showerror("Error", "Password must not be empty!")
        return

    # Encrypt the file using DES algorithm calling the encrypt_file_des function
    encrypted_filepath = encrypt_file_des(filepath, password)
    
    # If the encryption is successful
    if encrypted_filepath:
        messagebox.showinfo("Encryption Complete", f"File encrypted as {encrypted_filepath}")

def decrypt_file_des_with_password():
    """ 
    Decrypt a file using DES algorithm when the user clicks the "Decrypt File" button.
    Opens the decrypted file in the text editor.
    """
    # Ask user to select a file to decrypt
    filepath = tk.filedialog.askopenfilename(
        filetypes=[("Encrypted Files", "*.txt"), ("All Files", "*.*")]
    )
    if not filepath:
        return

    # Ask user to enter a password for decryption
    password = tk.simpledialog.askstring("Password", "Enter password for decryption:", show='*')
    if password is None:
        # User pressed the "Cancel" button
        return

    # If the password is empty
    if not password:
        messagebox.showerror("Error", "Password must not be empty!")
        return

    # Decrypt the file using DES algorithm calling the decrypt_file_des function
    decrypted_filepath = decrypt_file_des(filepath, password)
    
    # If the decryption is successful
    if decrypted_filepath:
        messagebox.showinfo("Decryption Complete", f"File decrypted as {decrypted_filepath}")
        display_decrypted_content(decrypted_filepath)  # Display decrypted content in text editor

## RSA encryption and decryption functions
# File paths for saving keys
PUBLIC_KEY_FILE = "public_key.pem"
PRIVATE_KEY_FILE = "private_key.pem"

# Function to generate RSA keys and save them to files
def generate_keys_and_save(keysize=2048):
    """
    Generate RSA public and private keys and save them to files.
    Default key size is 2048 bits.
    """
    try:
        # Generate RSA key pair
        random_generator = Random.new().read
        key = RSA.generate(keysize, random_generator)
        
        # Export public and private keys to strings
        public_key = key.publickey().export_key()
        private_key = key.export_key()
        
        # Save public key to file
        with open(PUBLIC_KEY_FILE, 'wb') as pub_key_file:
            pub_key_file.write(public_key)
        
        # Save private key to file
        with open(PRIVATE_KEY_FILE, 'wb') as priv_key_file:
            priv_key_file.write(private_key)
            
        # Show a message box when key generation and saving is successful
        messagebox.showinfo("Key Generation Complete", f"Public key saved as {PUBLIC_KEY_FILE}\nPrivate key saved as {PRIVATE_KEY_FILE}")
        
        # Show the keys in the console
        print(f"Public key: {public_key}")
        print(f"Private key: {private_key}")
        
        return public_key, private_key
    except Exception as e:
        # Handle key generation and saving errors
        messagebox.showerror("Error", f"Key generation and saving failed: {e}")

# Function to load existing RSA keys from files
def load_keys():
    """
    Load RSA keys from saved files.
    """
    try:
        # Load public and private keys from files
        with open(PUBLIC_KEY_FILE, 'rb') as pub_key_file:
            public_key = pub_key_file.read()
        
        with open(PRIVATE_KEY_FILE, 'rb') as priv_key_file:
            private_key = priv_key_file.read()
        
        return public_key, private_key
    except FileNotFoundError:
        # Show a warning if keys are not found
        messagebox.showwarning("Warning", "Keys not found. Please generate new keys.")
        return None, None
    except Exception as e:
        # Handle key loading errors
        messagebox.showerror("Error", f"Key loading failed: {e}")

# RSA encryption and decryption functions
def encrypt_file_rsa(filepath, public_key):
    """ 
    Encrypt a file using RSA public key.
    Return the encrypted file path if successful.
    """
    try:
        # Read file to be encrypted
        with open(filepath, 'rb') as file:
            data = file.read()
        
        # Import recipient's public key and create cipher
        recipient_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key) # Use PKCS1_OAEP padding scheme
        
        # Encrypt data
        encrypted_data = cipher_rsa.encrypt(data) # RSA encryption is slow for large data
        
        # Save encrypted data to a new file
        encrypted_filepath = filepath[:-4] + "-rsa-encrypted.txt" # Change the file extension
        with open(encrypted_filepath, 'wb') as file:
            file.write(encrypted_data)
            
        # Write encrypted data to console
        print(f"Encrypted data: {encrypted_data}")
        
        return encrypted_filepath
    except Exception as e:
        # Handle encryption errors
        messagebox.showerror("Encryption Failed", f"Error: {e}")

def decrypt_file_rsa(filepath, private_key):
    """ 
    Decrypt a file using RSA private key.
    Return the decrypted file path if successful.
    """
    try:
        # Read encrypted data from file
        with open(filepath, 'rb') as file:
            encrypted_data = file.read()
        
        # Import private key and create cipher
        key = RSA.import_key(private_key) # Import private key
        cipher_rsa = PKCS1_OAEP.new(key) # Use PKCS1_OAEP padding scheme
        
        # Decrypt data
        decrypted_data = cipher_rsa.decrypt(encrypted_data) # RSA decryption is slow for large data
        
        # Save decrypted data to a new file
        decrypted_filepath = filepath[:-4] + "-rsa-decrypted.txt" # Change the file extension
        with open(decrypted_filepath, 'wb') as file:
            file.write(decrypted_data)
            
        # Write decrypted data to console
        print(f"Decrypted data: {decrypted_data}")
        
        return decrypted_filepath
    except Exception as e:
        # Handle decryption errors
        messagebox.showerror("Decryption Failed", f"Error: {e}")

# Encryption and decryption functions called by the buttons
def encrypt_file_rsa_with_loaded_key():
    """
    Encrypt a file using loaded RSA public key when the user clicks the "Encrypt File (RSA)" button.
    """
    filepath = tk.filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if not filepath:
        return

    public_key, _ = load_keys()  # Assuming load_keys() returns the loaded public and private keys
    if public_key is None:
        return

    encrypted_filepath = encrypt_file_rsa(filepath, public_key) # Encrypt the file using RSA public key
    if encrypted_filepath:
        messagebox.showinfo("Encryption Complete", f"File encrypted as {encrypted_filepath}")

def decrypt_file_rsa_with_loaded_key():
    """ 
    Decrypt a file using loaded RSA private key when the user clicks the "Decrypt File (RSA)" button.
    """
    filepath = tk.filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if not filepath:
        return
    
    _, private_key = load_keys()  # Assuming load_keys() returns the loaded public and private keys
    if private_key is None:
        return
    
    decrypted_filepath = decrypt_file_rsa(filepath, private_key) # Decrypt the file using RSA private key
    if decrypted_filepath:
        display_decrypted_content(decrypted_filepath)  # Display decrypted content in text editor
        messagebox.showinfo("Decryption Complete", f"File decrypted as {decrypted_filepath}")


## Main program
# Create the main window
window = tk.Tk()
window.title("Text Editor with Encryption Algorithms")

# Set window size and layout
window.geometry("980x580")  # Set window size

# Create Text widget with scrollbar
txt_edit = scrolledtext.ScrolledText(window, wrap=tk.WORD, font=("Arial", 12))

# Create Buttons
btn_open = tk.Button(window, text="Open", width=10, command=open_file)
btn_save = tk.Button(window, text="Save As...", width=10, command=save_file)
btn_dark_mode = tk.Button(window, text="Toggle Dark", width=10, command=toggle_dark_mode)
btn_clear = tk.Button(window, text="Clear", width=10, command=clear_text)

btn_about = tk.Button(window, text="About", width=25, height=2, command=about_info)
btn_des_encrypt = tk.Button(window, text="Encrypt from Files... (DES)", width=25, height=2, bg="lightblue", fg="black", command=encrypt_file_des_with_password)
btn_des_decrypt = tk.Button(window, text="Decrypt from Files... (DES)", width=25, height=2, bg="lightblue", fg="black", command=decrypt_file_des_with_password)

btn_generate_keys = tk.Button(window, text="Generate Keys (RSA)", width=25, height=2, bg="lightpink", fg="black",command=generate_keys_and_save)
btn_rsa_encrypt = tk.Button(window, text="Encrypt from Files... (RSA)", width=25, height=2, bg="lightpink", fg="black", command=encrypt_file_rsa_with_loaded_key)
btn_rsa_decrypt = tk.Button(window, text="Decrypt from Files... (RSA)", width=25, height=2, bg="lightpink", fg="black", command=decrypt_file_rsa_with_loaded_key)

# Create Menubar
menubar = Menu(window)
file_menu = Menu(menubar, tearoff=0)
file_menu.add_command(label="Open", command=open_file)
file_menu.add_command(label="Save As...", command=save_file)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=window.quit)
menubar.add_cascade(label="File", menu=file_menu)
window.config(menu=menubar)

# Create Labels for line, word, and character count
lbl_line_count = tk.Label(window, text="Lines: 0")
lbl_word_count = tk.Label(window, text="Words: 0")
lbl_char_count = tk.Label(window, text="Characters: 0")

# Label for key warning
lbl_key_warning = tk.Label(window, text="Save the file before encrypting.\nGenerate keys before RSA encryption if you haven't!", fg="red")

# Place widgets in the window using grid layout
txt_edit.grid(row=0, column=0, rowspan=6, columnspan=4, padx=10, pady=10)
btn_open.grid(row=6, column=0, padx=5, pady=5)
btn_save.grid(row=6, column=1, padx=5, pady=5)
btn_dark_mode.grid(row=6, column=2, padx=5, pady=5)
btn_clear.grid(row=6, column=3, padx=5, pady=5)
btn_about.grid(row=0, column=4, padx=5, pady=5)

btn_des_encrypt.grid(row=1, column=4, padx=5, pady=5)
btn_des_decrypt.grid(row=2, column=4, padx=5, pady=5)

btn_generate_keys.grid(row=3, column=4, padx=5, pady=5)
btn_rsa_encrypt.grid(row=4, column=4, padx=5, pady=5)
btn_rsa_decrypt.grid(row=5, column=4, padx=5, pady=5)

lbl_line_count.grid(row=7, column=0, padx=5, pady=5)
lbl_word_count.grid(row=7, column=1, padx=5, pady=5)
lbl_char_count.grid(row=7, column=2, padx=5, pady=5)

lbl_key_warning.grid(row=8, column=0, columnspan=4, padx=5, pady=5)

# Bind events to text editing (e.g., typing, deleting) to update counts dynamically
txt_edit.bind('<Key>', update_counts)
txt_edit.bind('<BackSpace>', update_counts)

# Start the application
window.mainloop()