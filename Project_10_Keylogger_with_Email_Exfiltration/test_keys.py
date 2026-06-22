# test_keys.py
from pynput.keyboard import Key, Listener

def on_press(key):
    print(f"Raw key object: {key}")
    print(f"Type: {type(key)}")
    print(f"Repr: {repr(key)}")
    
    if hasattr(key, 'char'):
        print(f"char attribute: '{key.char}'")
    
    # Try to convert to string
    try:
        if hasattr(key, 'char') and key.char:
            print(f"Converted: '{key.char}'")
        elif key == Key.space:
            print("Converted: ' '")
        elif key == Key.enter:
            print("Converted: '\\n'")
        else:
            print(f"Special key: {key}")
    except Exception as e:
        print(f"Error: {e}")
    
    print("-" * 40)

print("Press any key (Ctrl+C to stop):")
with Listener(on_press=on_press) as listener:
    try:
        listener.join()
    except KeyboardInterrupt:
        print("\nStopped")