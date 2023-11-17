import tkinter as tk
from tkinter import messagebox, scrolledtext, Menu, filedialog

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
    messagebox.showinfo("About", "A Simple Text Editor with Encryption Algorithms!\nNguyen Viet Ha s3978128\nSecurity for Computing and IT")

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
    characters = len(text) - text.count('\n')  # Excluding newline characters

    lbl_line_count.config(text=f"Lines: {lines}")
    lbl_word_count.config(text=f"Words: {words}")
    lbl_char_count.config(text=f"Characters: {characters}")

# Create the main window
window = tk.Tk()
window.title("Text Editor")

# Set window size and layout
window.geometry("880x550")  # Set window size
window.resizable(False, False)  # Set resizable to False for both x and y directions

# Create Text widget with scrollbar
txt_edit = scrolledtext.ScrolledText(window, wrap=tk.WORD, font=("Arial", 12))

# Create Buttons
btn_open = tk.Button(window, text="Open", width=10, command=open_file)
btn_save = tk.Button(window, text="Save As...", width=10, command=save_file)
btn_about = tk.Button(window, text="About", width=10, command=about_info)
btn_clear = tk.Button(window, text="Clear", width=10, command=clear_text)
btn_dark_mode = tk.Button(window, text="Dark Mode", width=10, command=toggle_dark_mode)

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

# Place widgets in the window using grid layout
txt_edit.grid(row=0, column=0, rowspan=6, columnspan=4, padx=10, pady=10)
btn_open.grid(row=6, column=0, padx=5, pady=5)
btn_save.grid(row=6, column=1, padx=5, pady=5)
btn_about.grid(row=6, column=2, padx=5, pady=5)
btn_clear.grid(row=6, column=3, padx=5, pady=5)
btn_dark_mode.grid(row=0, column=4, padx=5, pady=5)
lbl_line_count.grid(row=7, column=0, padx=5, pady=5)
lbl_word_count.grid(row=7, column=1, padx=5, pady=5)
lbl_char_count.grid(row=7, column=2, padx=5, pady=5)

# Bind events to text editing (e.g., typing, deleting) to update counts dynamically
txt_edit.bind('<Key>', update_counts)
txt_edit.bind('<BackSpace>', update_counts)

# Start the application
window.mainloop()