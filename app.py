from flask import Flask, request, render_template, jsonify
import random
import math
import struct

app = Flask(__name__)

# --- Helper Functions ---

# Linear Congruential Generator (LCG) for generating two prime numbers
def lcg_for_rsa(seed, m=2**32, a=1664525, c=1013904223):
    def is_prime(n):
        if n <= 1:
            return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                return False
        return True

    x = seed
    primes = []
    while len(primes) < 2:  # Generate two prime numbers
        x = (a * x + c) % m
        candidate = x % 1000  # Limit the range to avoid very large numbers
        if candidate > 1 and is_prime(candidate):  # Ensure it's a prime number
            primes.append(candidate)
    return primes[0], primes[1]  # Return p and q

# RSA Key Generation using LCG-generated primes
def generate_rsa_keys():
    # Generate two prime numbers using LCG
    seed = random.randint(1, 1000000)
    p, q = lcg_for_rsa(seed)

    # Calculate RSA parameters
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Select e such that gcd(e, phi_n) = 1
    while True:
        e = random.randint(2, phi_n - 1)
        if math.gcd(e, phi_n) == 1:
            break

    # Compute d such that (d * e) mod phi_n = 1
    d = pow(e, -1, phi_n)
    
    print(f"q : {q} \np : {p}\ne : {e}\nphi_n : {phi_n}\nd : {d}")
    return {'public_key': (n, e), 'private_key': (n, d)}

# XOR function for encryption/decryption
def xor_bytes(byte1, byte2):
    return bytes([b1 ^ b2 for b1, b2 in zip(byte1, byte2)])

# CTR Mode Encryption/Decryption
def ctr_mode(text, key, encrypt=True):
    block_size = 16  # AES block size in bytes
    blocks = (len(text) + block_size - 1) // block_size
    result = bytearray()

    for i in range(blocks):
        counter_block = i.to_bytes(block_size, byteorder='big')
        keystream = xor_bytes(counter_block, key[:block_size])  # Simulate keystream
        text_block = text[i * block_size:(i + 1) * block_size]
        output_block = xor_bytes(text_block, keystream[:len(text_block)])
        result.extend(output_block)

    return bytes(result)

# SHA-1 Implementation
def sha1(message):
    # Step 1: Convert message to bytes using UTF-8 encoding
    message_bytes = message
    # print(f"Step 1: Message in bytes (Hex) = {bytes_to_hex(message_bytes)}")

    # Step 2: Pad the message according to SHA-1 specification
    padded_message = pad_message(message_bytes)
    # print(f"Step 2: Padded message (Hex) = {bytes_to_hex(padded_message)}")

    # Step 3: Initialize the 5 SHA-1 hash values (h0 to h4)
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # print("Step 3: Initial hash values:")
    # print(f"h0 = {h0:08x}, h1 = {h1:08x}, h2 = {h2:08x}, h3 = {h3:08x}, h4 = {h4:08x}")

    # Step 4: Process each 512-bit (64-byte) block of the padded message
    words = [0] * 80  # Array to hold 80 words for SHA-1 processing
    for i in range(0, len(padded_message), 64):
        # print("\nProcessing a 512-bit block...\n")

        # Step 4.1: Create the first 16 words W[0..15] from the 512-bit block
        # print("Step 4.1: Creating first 16 words (W0 - W15)...")
        for j in range(16):
            index = i + j * 4  # Calculate byte index in the block

            # Convert 4 bytes to 1 int (big-endian order)
            words[j] = struct.unpack('>I', padded_message[index:index + 4])[0]
            # print(f"W[{j}] = {words[j]:08x}")

        # Step 4.2: Extend the 16 words to 80 words using XOR and rotation
        # print("\nStep 4.2: Expanding words from W16 to W79...\n")
        for j in range(16, 80):
            words[j] = left_rotate(words[j - 3] ^ words[j - 8] ^ words[j - 14] ^ words[j - 16], 1)
            # print(f"W[{j}] = {words[j]:08x}")

        # print("Step 4 complete!\n")

        # Step 5: Initialize working variables with the current hash values
        a, b, c, d, e = h0, h1, h2, h3, h4
        # print("Step 5 Completed")

        # Step 6: Perform the main loop of 80 rounds
        for j in range(80):
            if j < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif j < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif j < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            # Compute temporary value and update working variables
            temp = left_rotate(a, 5) + f + e + k + words[j] & 0xFFFFFFFF
            e = d
            d = c
            c = left_rotate(b, 30)  # Rotate b by 30 bits
            b = a
            a = temp

            # Print values every 20 rounds for debugging
            # if j % 20 == 0:
                # print(f"Round {j}: a={a:08x}, b={b:08x}, c={c:08x}, d={d:08x}, e={e:08x}")

        # print("Step 6 Completed")

        # Step 7: Add this block's hash to result so far
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        # print("Step 7 Completed")

    # Step 8: Concatenate the final hash values into a single hex string
    final_hash = f"{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}"
    # print(f"\nStep 8: Final SHA-1 Hash = {final_hash}")
    # print("Step 8 Completed")
    # print("All process Completed Successfully!")

    # Return the final SHA-1 hash
    return final_hash


# Helper function to pad the message
def pad_message(message_bytes):
    original_length = len(message_bytes)
    padded_length = ((original_length + 8) // 64 + 1) * 64
    padded_message = bytearray(padded_length)

    # Copy original message
    padded_message[:original_length] = message_bytes

    # Append '1' bit (10000000 in binary)
    padded_message[original_length] = 0x80

    # Append 64-bit message length (big-endian)
    message_bit_length = original_length * 8
    for i in range(8):
        padded_message[padded_length - 8 + i] = (message_bit_length >> (8 * (7 - i))) & 0xFF

    return bytes(padded_message)


# Helper function to convert bytes to hex string
def bytes_to_hex(bytes_data):
    return ''.join(f'{byte:02x}' for byte in bytes_data)


# Helper function for left rotation
def left_rotate(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        plaintext = data.get('text')
        key_type = data.get('key_type')
        custom_key = data.get('key')

        # Validate inputs
        if not plaintext:
            return jsonify({'error': "Plaintext is required."})

        # Generate key based on type
        if key_type == 'rsa':
            keys = generate_rsa_keys()
            key = keys['public_key'][0].to_bytes(16, 'big')  # Simplified for demo
        elif key_type == 'custom':
            if not custom_key:
                return jsonify({'error': "Custom key is required."})
            try:
                key = bytes.fromhex(custom_key)[:16]
            except ValueError:
                return jsonify({'error': "Invalid custom key format. Please provide a valid hex string."})
        else:
            return jsonify({'error': "Invalid key type."})

        # Encrypt the plaintext using UTF-8 encoding
        ciphertext = ctr_mode(plaintext.encode('utf-8'), key)

        # Generate SHA-1 hash of the plaintext
        plaintext_hash = sha1(plaintext.encode('utf-8'))

        return jsonify({
            'result': ciphertext.hex(),
            'key': key.hex(),
            'sha1_hash': plaintext_hash
        })
    except Exception as e:
        return jsonify({'error': f"Encryption failed: {str(e)}"})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        ciphertext_hex = data.get('text')
        decryption_key = data.get('key')
        stored_sha1_hash = data.get('sha1_hash')

        # Validate inputs
        if not ciphertext_hex or not decryption_key or not stored_sha1_hash:
            return jsonify({'error': "Ciphertext, decryption key, and SHA-1 hash are required."})

        # Convert hex strings to bytes
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
            key = bytes.fromhex(decryption_key)[:16]
        except ValueError:
            return jsonify({'error': "Invalid input format. Please provide valid hex strings."})

        # Decrypt the ciphertext
        plaintext = ctr_mode(ciphertext, key)

        # Decode using UTF-8, fallback to hex if decoding fails
        try:
            plaintext_str = plaintext.decode('utf-8')
        except UnicodeDecodeError:
            plaintext_str = plaintext.hex()  # Return as hex string if UTF-8 decoding fails

        # Verify SHA-1 hash
        calculated_hash = sha1(plaintext)
        if calculated_hash != stored_sha1_hash:
            return jsonify({'error': "SHA-1 hash mismatch. Data integrity check failed."})

        return jsonify({'result': plaintext_str})
    except Exception as e:
        return jsonify({'error': f"Decryption failed: {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True)