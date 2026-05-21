// Show/hide custom key input based on key type selection
document.getElementById('encrypt-key-type').addEventListener('change', function () {
    const customKeyInput = document.getElementById('encrypt-custom-key');
    if (this.value === 'custom') {
        customKeyInput.style.display = 'block';
    } else {
        customKeyInput.style.display = 'none';
    }
});

// Encrypt Button Click
document.getElementById('encrypt-btn').addEventListener('click', async () => {
    const plaintext = document.getElementById('plaintext').value.trim();
    const keyType = document.getElementById('encrypt-key-type').value;
    const customKey = document.getElementById('encrypt-custom-key').value.trim();

    // Validate input
    if (!plaintext) {
        alert("Please enter plaintext.");
        return;
    }
    if (keyType === 'custom' && !customKey) {
        alert("Please enter a custom key.");
        return;
    }

    try {
        const response = await fetch('/encrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: plaintext, key_type: keyType, key: customKey }),
        });

        const data = await response.json();
        if (data.error) {
            alert(`Error: ${data.error}`);
        } else {
            // Display ciphertext, key, and SHA-1 hash
            document.getElementById('encrypt-ciphertext').textContent = data.result;
            document.getElementById('encrypt-key').textContent = data.key || 'Generated';
            document.getElementById('encrypt-sha1-hash').textContent = data.sha1_hash;
            document.getElementById('encrypt-result').style.display = 'block';
        }
    } catch (error) {
        alert(`An error occurred: ${error.message}`);
    }
});

// Decrypt Button Click
document.getElementById('decrypt-btn').addEventListener('click', async () => {
    const ciphertextHex = document.getElementById('ciphertext').value.trim();
    const decryptionKey = document.getElementById('decrypt-key').value.trim();
    const sha1Hash = document.getElementById('decrypt-sha1-hash').value.trim();

    // Validate input
    if (!ciphertextHex) {
        alert("Please enter ciphertext.");
        return;
    }
    if (!decryptionKey) {
        alert("Please enter a decryption key.");
        return;
    }
    if (!sha1Hash) {
        alert("Please enter the SHA-1 hash of the original plaintext.");
        return;
    }

    try {
        const response = await fetch('/decrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: ciphertextHex, key: decryptionKey, sha1_hash: sha1Hash }),
        });

        const data = await response.json();
        if (data.error) {
            alert(`Error: ${data.error}`);
        } else {
            // Display plaintext and SHA-1 verification result
            document.getElementById('decrypt-plaintext').textContent = data.result;
            document.getElementById('decrypt-sha1-verification').textContent = "Verified";
            document.getElementById('decrypt-result').style.display = 'block';
        }
    } catch (error) {
        alert(`An error occurred: ${error.message}`);
    }
});