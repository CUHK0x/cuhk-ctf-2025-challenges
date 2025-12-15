import sys

# HID keycode to character mapping
HID_KEYCODE_MAP = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e', 0x09: 'f', 0x0A: 'g',
    0x0B: 'h', 0x0C: 'i', 0x0D: 'j', 0x0E: 'k', 0x0F: 'l', 0x10: 'm', 0x11: 'n',
    0x12: 'o', 0x13: 'p', 0x14: 'q', 0x15: 'r', 0x16: 's', 0x17: 't', 0x18: 'u',
    0x19: 'v', 0x1A: 'w', 0x1B: 'x', 0x1C: 'y', 0x1D: 'z',
    0x1E: '1', 0x1F: '2', 0x20: '3', 0x21: '4', 0x22: '5', 0x23: '6', 0x24: '7',
    0x25: '8', 0x26: '9', 0x27: '0',
    0x2C: ' ', 0x2D: '-', 0x2E: '=', 0x2F: '[', 0x30: ']', 0x31: '\\', 0x33: ';',
    0x34: "'", 0x35: '`', 0x36: ',', 0x37: '.', 0x38: '/',
    0x28: '\n',  # Enter
    0x2A: '',    # Backspace (handle separately)
}

# Shift modifier mapping for symbols
SHIFT_MAP = {
    '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&', '8': '*',
    '9': '(', '0': ')', '-': '_', '=': '+', '[': '{', ']': '}', '\\': '|', ';': ':',
    "'": '"', '`': '~', ',': '<', '.': '>', '/': '?'
}

def decode_hid_data(hex_string):
    """Decode a single HID data packet"""
    if not hex_string or len(hex_string) < 16:  # Need at least 8 bytes (16 hex chars)
        return ''
    
    try:
        # Convert hex string to bytes
        data = bytes.fromhex(hex_string.replace(':', ''))
    except:
        return ''
    
    if len(data) < 8:
        return ''
    
    # HID data format: [modifier, reserved, keycode1, keycode2, keycode3, keycode4, keycode5, keycode6]
    modifier = data[0]
    keycode = data[2]  # The key pressed is the third byte

    # Skip key release events and non-character keys
    if keycode == 0:
        return ''

    if keycode in HID_KEYCODE_MAP:
        char = HID_KEYCODE_MAP[keycode]
        
        # Apply Shift modifier
        if modifier & 0x20:  # Left Shift pressed
            if char.isalpha():
                char = char.upper()
            else:
                char = SHIFT_MAP.get(char, char)
        
        return char
    else:
        return f'[0x{keycode:02X}]'

def main():
    # Read HID data from file
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            lines = f.readlines()
    else:
        print("Usage: python solve.py hid_data.txt")
        return
    
    full_text = ""
    
    for line in lines:
        line = line.strip()
        if line:
            decoded_char = decode_hid_data(line)
            full_text += decoded_char
    
    print("Full decoded text:")
    print("=" * 50)
    print(full_text)
    print("=" * 50)
    
    # Look for CTF flags
    import re
    flags = re.findall(r'(cuhk25ctf\{[^}]+\}|CTF\{[^}]+\})', full_text)
    if flags:
        print(f"\n🎉 Found flag: {flags[0]}")


if __name__ == "__main__":
    main()    
