import tkinter as tk
from tkinter import messagebox
import random
import os

# Sample images for the graphical password
images = ["Dairy Milk", "KitKat", "5 Stars", "Perk", "Snickers"]

# Global variables
pattern_file = "pattern.txt"

# Helper function to save the registered pattern
def save_pattern(pattern):
    with open(pattern_file, "w") as file:
        file.write(",".join(pattern))

# Helper function to load the registered pattern
def load_pattern():
    if os.path.exists(pattern_file):
        with open(pattern_file, "r") as file:
            return file.read().split(",")
    return None

# Shuffle images and create buttons dynamically
def create_image_buttons(frame, callback):
    shuffled_images = random.sample(images, len(images))
    for img in shuffled_images:
        btn = tk.Button(frame, text=img, width=20, height=2, command=lambda i=img: callback(i))
        btn.pack(pady=5)

# Registration window
def register_window():
    selected_pattern = []

    def register_image(image):
        if image not in selected_pattern:
            selected_pattern.append(image)
            pattern_label.config(text=" -> ".join(selected_pattern))

    def complete_registration():
        if len(selected_pattern) < 3:
            messagebox.showerror("Error", "Select at least 3 images!")
        else:
            save_pattern(selected_pattern)
            messagebox.showinfo("Success", "Registration Complete! Pattern saved.")
            reg_window.destroy()

    reg_window = tk.Toplevel(root)
    reg_window.title("Register")
    reg_window.geometry("400x400")

    tk.Label(reg_window, text="Register Your Pattern", font=("Arial", 16)).pack(pady=10)
    pattern_label = tk.Label(reg_window, text="Your Pattern: ", font=("Arial", 12))
    pattern_label.pack(pady=10)

    frame = tk.Frame(reg_window)
    frame.pack(pady=10)

    create_image_buttons(frame, register_image)
    tk.Button(reg_window, text="Complete Registration", command=complete_registration).pack(pady=10)

# Login window
def login_window():
    selected_pattern = []

    def login_image(image):
        if len(selected_pattern) < len(stored_pattern):
            selected_pattern.append(image)
            login_label.config(text=" -> ".join(selected_pattern))

    def verify_login():
        if selected_pattern == stored_pattern:
            messagebox.showinfo("Success", "Login Successful!")
        else:
            messagebox.showerror("Error", "Login Failed!")
        login_window.destroy()

    stored_pattern = load_pattern()
    if not stored_pattern:
        messagebox.showerror("Error", "No registered pattern found. Please register first.")
        return

    login_window = tk.Toplevel(root)
    login_window.title("Login")
    login_window.geometry("400x400")

    tk.Label(login_window, text="Login with Your Pattern", font=("Arial", 16)).pack(pady=10)
    login_label = tk.Label(login_window, text="Your Pattern: ", font=("Arial", 12))
    login_label.pack(pady=10)

    frame = tk.Frame(login_window)
    frame.pack(pady=10)

    create_image_buttons(frame, login_image)
    tk.Button(login_window, text="Verify Login", command=verify_login).pack(pady=10)

# Main window
root = tk.Tk()
root.title("Graphical Password Authentication")
root.geometry("400x400")

tk.Label(root, text="Graphical Password Authentication", font=("Arial", 16)).pack(pady=20)

tk.Button(root, text="Register", font=("Arial", 14), command=register_window).pack(pady=10)
tk.Button(root, text="Login", font=("Arial", 14), command=login_window).pack(pady=10)

root.mainloop()
