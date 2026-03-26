# Cryptanalysis of the A5/1 Stream Cipher program

import os
from tqdm import tqdm

def check_file_exists(path):
    if not os.path.isfile(path):
        print(f"File not found: {path}")
        return False
    print(f"File found: {path}")
    return True

def check_initial_states(path):
    try:
        with open(path, 'r') as f:
            lines = f.read().splitlines()
            if len(lines) != 2:
                print("initial_states.txt must contain exactly 2 lines.")
                return False
            x_state = lines[0].strip()
            z_state = lines[1].strip()
            if len(x_state) != 19:
                print(f"X state must be 19 bits. Got {len(x_state)}")
                return False
            if len(z_state) != 23:
                print(f"Z state must be 23 bits. Got {len(z_state)}")
                return False
            print("initial_states.txt is valid.")
            print(f"    X: {x_state}")
            print(f"    Z: {z_state}")
            return True
    except Exception as e:
        print(f"Error reading initial_states.txt: {e}")
        return False

def check_known_plaintext(path):
    try:
        with open(path, 'r') as f:
            text = f.read().strip()
            if not text:
                print("known_plaintext.txt is empty.")
                return False
            print(f"known_plaintext.txt is valid. Length: {len(text)} characters.")
            preview = text[:50] + ("..." if len(text) > 50 else "")
            print(f"    Preview: \"{preview}\"")
            return True
    except Exception as e:
        print(f"Error reading known_plaintext.txt: {e}")
        return False

def check_ciphertext(path):
    try:
        with open(path, 'r') as f:
            data = f.read().strip()
        if not data:
            print("ciphertext.bin is empty.")
            return False
        if any(ch not in '01' for ch in data):
            print("ciphertext.bin contains characters other than '0' or '1'.")
            return False
        print(f"ciphertext.bin is valid. Total bits: {len(data)}")
        preview_bits = data[:64] + ("..." if len(data) > 64 else "")
        print(f"    Preview bits: {preview_bits}")
        return True
    except Exception as e:
        print(f"Error reading ciphertext.bin: {e}")
        return False

# Helper Functions

class LFSR:
    def __init__(self, state, taps):
        self.state = list(map(int, state))
        self.taps = taps

    def clock(self):
        feedback = 0
        for t in self.taps:
            feedback ^= self.state[t]
        output = self.state[-1]
        self.state = [feedback] + self.state[:-1]
        return output
# Calculate the majority bit to decide if x or y or z will be shifted
def majority(a, b, c):
    return 1 if a + b + c >= 2 else 0

def str_to_bits(s):
    return [int(bit) for byte in s.encode() for bit in format(byte, '08b')]

def bits_to_string(bits):
    chars = []
    for b in range(0, len(bits), 8):
        byte = bits[b:b+8]
        if len(byte) < 8:
            break
        chars.append(chr(int(''.join(map(str, byte)), 2)))
    return ''.join(chars)

def decrypt(cipher_bits, keystream):
    return [cb ^ kb for cb, kb in zip(cipher_bits, keystream)]

# Function to generate keystream
def generate_keystream(x_init, y_init, z_init, length):
    # Initialize each LFSR with its initial state and feedback bits
    lfsr_x = LFSR(x_init, [13, 16, 17, 18])
    lfsr_y = LFSR(y_init, [20, 21])
    lfsr_z = LFSR(z_init, [7, 20, 21, 22])
    keystream = []
    for _ in range(length):
        m = majority(lfsr_x.state[8], lfsr_y.state[10], lfsr_z.state[10])
        if lfsr_x.state[8] == m:
            lfsr_x.clock()
        if lfsr_y.state[10] == m:
            lfsr_y.clock()
        if lfsr_z.state[10] == m:
            lfsr_z.clock()
        ks_bit = lfsr_x.state[-1] ^ lfsr_y.state[-1] ^ lfsr_z.state[-1]
        keystream.append(ks_bit)
    return keystream



def main():
    print("A5/1 Stream Cipher Attack Tool\n")

    initial_path = input("Enter path to initial_states.txt: ").strip()
    if not check_file_exists(initial_path) or not check_initial_states(initial_path):
        return

    plaintext_path = input("\nEnter path to known_plaintext.txt: ").strip()
    if not check_file_exists(plaintext_path) or not check_known_plaintext(plaintext_path):
        return

    ciphertext_path = input("\nEnter path to ciphertext.bin: ").strip()
    if not check_file_exists(ciphertext_path) or not check_ciphertext(ciphertext_path):
        return

    # Load files
    with open(initial_path, 'r') as f:
        x_init = f.readline().strip()
        z_init = f.readline().strip()

    with open(plaintext_path, 'r') as f:
        known_plaintext = f.read().strip()
        known_plaintext_bits = str_to_bits(known_plaintext)

    with open(ciphertext_path, 'r') as f:
        cipher_bitstring = f.read().strip()
        ciphertext_bits = [int(b) for b in cipher_bitstring]

# We used partial keystream match first 24 bits to speed up brute-force search.

    print("\nStarting Brute-Force to Recover LFSR Y (partial match)")

    trial_length = 24
    recovered_y = None

    for y in tqdm(range(2**22)):
        y_init = format(y, '022b')
        ks = generate_keystream(x_init, y_init, z_init, trial_length)
        decrypted = decrypt(ciphertext_bits[:trial_length], ks)
        if decrypted == known_plaintext_bits[:trial_length]:
            recovered_y = y_init
            print(f"\nRecovered LFSR Y: {recovered_y}")
            break

    if not recovered_y:
        print("\nFailed to recover LFSR Y")
        return

    with open("recovered_y_state.txt", "w") as f:
        f.write(recovered_y)

    print("Decrypting full ciphertext")
    ks_full = generate_keystream(x_init, recovered_y, z_init, len(ciphertext_bits))
    full_decrypted = decrypt(ciphertext_bits, ks_full)
    plaintext_result = bits_to_string(full_decrypted)

    with open("recovered_plaintext.txt", "w", encoding="utf-8") as f:
        f.write(plaintext_result)

    print("\nSuccess! Results saved to:")
    print("   - recovered_y_state.txt")
    print("   - recovered_plaintext.txt")

if __name__ == "__main__":
    main()
