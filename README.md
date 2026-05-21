# CryptX 🔒 - Custom Cryptographic Web Dashboard

An interactive, responsive Flask-based web application showcasing custom, low-level implementations of asymmetric, symmetric, and hashing cryptographic algorithms from scratch in Python—completely bypassing high-level cryptographic libraries.

This project is a powerful portfolio showpiece demonstrating mathematical logic, bitwise manipulation, low-level block structures, and data integrity verification.

---

## 🚀 Key Features

* **Custom RSA Key Generation:** Uses a customized Linear Congruential Generator (LCG) to generate and screen prime numbers, compute keys, and perform modular arithmetic.
* **Custom CTR Mode Symmetric Encryption:** A 16-byte block cipher operating in Counter (CTR) mode, using bitwise XOR and simulated keystreams.
* **Pure Python SHA-1 Hash Implementation:** A standard-compliant implementation of the FIPS PUB 180-1 SHA-1 algorithm, featuring bit-padding, 80-round loop compression, and custom registers.
* **Integrity & Verification Portal:** The application automatically verifies the SHA-1 hash integrity of the decrypted data to detect any manipulation or key mismatch.
* **Premium Modern UI:** A responsive, sleek web dashboard styling with dynamic frontend controls.

---

## 🧮 Algorithmic Breakdown

### 1. Asymmetric Cryptography: RSA with Custom Prime LCG
Standard RSA relies on highly complex prime generation. This project implements a fully customized flow:
* **LCG Candidate Generation:** Seeds a Linear Congruential Generator using:
  $$X_{n+1} = (a \cdot X_n + c) \pmod m$$
  *(where $a = 1,664,525$, $c = 1,013,904,223$, and $m = 2^{32}$)* to dynamically sample candidates.
* **Trial Division Screening:** Screens candidates using $O(\sqrt{N})$ trial division to verify primality.
* **Key Derivation:**
  * Calculates modulus: $n = p \cdot q$
  * Calculates Euler's totient: $\phi(n) = (p-1)(q-1)$
  * Samples public exponent $e$ such that $\gcd(e, \phi(n)) = 1$
  * Derives private key exponent $d$ using the Modular Multiplicative Inverse: $d \equiv e^{-1} \pmod{\phi(n)}$

### 2. Symmetric Cryptography: Block Cipher in Counter (CTR) Mode
Symmetric encryption processes data block by block:
* **16-byte Block Counter:** Simulates a counter block using big-endian serialization (`big-endian`).
* **Keystream Simulation:** XORs the counter block byte-by-byte with the secret key to build a dynamic, non-repeating keystream.
* **Bitwise XOR Operation:** Encrypts or decrypts by XORing the plaintext/ciphertext bytes against the keystream. CTR mode makes encryption and decryption symmetric operations.

### 3. Hash Function: FIPS PUB 180-1 SHA-1
Integrity checks are processed via a pure Python implementation of SHA-1:
* **Custom Padding:** Appends a `0x80` byte to the message, pads with trailing `0x00` bytes to align to a multiple of 64 bytes (with 8 bytes remaining), and appends the original bit-length as a 64-bit big-endian integer.
* **Register Initialization:** Employs the five classic 32-bit buffer constants:
  * $H_0 = \text{0x67452301}$, $H_1 = \text{0xEFCDAB89}$, $H_2 = \text{0x98BADCFE}$, $H_3 = \text{0x10325476}$, $H_4 = \text{0xC3D2E1F0}$
* **Message Expansion:** Unpacks 512-bit blocks using `struct.unpack('>I', ...)` into 16 words, then expands them into 80 words through cyclic left-rotations:
  $$W_j = (W_{j-3} \oplus W_{j-8} \oplus W_{j-14} \oplus W_{j-16}) \lll 1$$
* **80-Round Loop Compression:** Applies the logic functions $f(t; B, C, D)$ and round constants $K_t$ across four distinct intervals of 20 rounds each, updating internal variables $A, B, C, D, E$ at each iteration.

---

## 📁 Repository Structure

```text
CryptX/
│
├── app.py                # Main Flask server with custom crypto algorithms
├── CryptX.pptx           # Academic slides detailing the implementation
├── CryptX.pdf            # PDF version of the presentation slides
├── requirements.txt      # Project library dependencies (Flask)
├── .gitignore            # Git exclusion configuration
│
├── templates/
│   ├── index.html        # Main dashboard interface
│   └── title.html        # Title/header layout component
│
└── static/
    ├── styles.css        # Premium glassmorphic styling sheet
    └── script.js         # AJAX request handling and frontend validation
```

---

## 🛠️ Local Installation & Run

1. **Clone the repository:**
   ```bash
   git clone https://github.com/BnEhab2/cryptx-crypto-dashboard.git
   cd cryptx-crypto-dashboard
   ```

2. **Set up a Virtual Environment (Optional but Recommended):**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application:**
   ```bash
   python app.py
   ```

5. **Access the Web Dashboard:**
   Open your browser and navigate to `http://127.0.0.1:5000`

---

## 📝 Academic Notes & Presentation
This repository contains a full presentation of the mathematics and architectural details of this software in both PowerPoint (`CryptX.pptx`) and PDF (`CryptX.pdf`) formats. Feel free to open them to explore the underlying formulas, algorithms, and design choices.

---

## 🛡️ License
Distributed under the MIT License. See `LICENSE` for more information.
