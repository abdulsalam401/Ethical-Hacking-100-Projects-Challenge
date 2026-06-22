# test_simple.py
from pynput.keyboard import Key, Listener

def on_press(key):
    print(f"Key: {key}")  # This should print every key

print("Press any key (Ctrl+C to stop):")
with Listener(on_press=on_press) as listener:
    try:
        listener.join()
    except KeyboardInterrupt:
        print("\nStopped")