# Secure Text Editor

The Secure Text Editor is an application built using Python's `tkinter` library, offering encryption functionalities for text files using `pyDes` and `pycryptodome`.

## Features:

### Encryption Options:
- **DES Encryption:** Encrypt files using the symmetric DES (Data Encryption Standard) algorithm.
- **RSA Encryption:** Employ asymmetric RSA (Rivest-Shamir-Adleman) encryption for secure file handling.

### Text Editing:
- **Open File:** Access and edit text files (supports .txt and various file formats).
- **Save As:** Save the current content to a chosen file.
- **Clear:** Empty the text editor's content.
- **Dark Mode:** Switch between light and dark themes for better readability.
- **About**: Provides information about the application.
- **Counters**: Dynamically counts the number of lines, words, and characters in the text being edited.

## How to Use:

### Requirements:
- Ensure Python 3.x is installed on your system.

### Installation:
1. Clone or download the repository to your local machine.
2. If necessary, install the required Python packages (`tkinter`, `pyDes`, `pycryptodome`).

### Running the Application:
1. Open a terminal.
2. Navigate to the directory where the `text_editor.py` file is.
3. Execute the following command:
    ```
    python text_editor.py
    ```
4. The application window will appear, enabling you to perform text editing operations with encryption capabilities (DES or RSA encryption available). You can start by encrypting the provided `testingtext.txt` file, or create a new file.
5. To use the DES encryption, you need to input a non-empty password. Note that due to limitations, passwords longer than 8 characters will be truncated.
6. To use the RSA encryption, a pair of public and private keys is needed. Use the Generate Key button to generate the keys. You can then start using this encryption method.

## Information:
- **Author:** Nguyen Viet Ha (s3978128)
- **Course:** Security for Computing and IT
