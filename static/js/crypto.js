// --- crypto.js ---

let cryptoKey = null;

// Derived key from the password user enters
async function deriveKey(password) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    
    // We use a fixed salt for simplicity in this demo (In prod, salt should be unique per room)
    const salt = enc.encode("mugiwara-salt-v1");

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// Encrypt message
async function encryptMessage(text) {
    if (!cryptoKey) return null;
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Initialization Vector
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        cryptoKey,
        enc.encode(text)
    );

    // Convert buffer to Base64 string for storage
    const ivArray = Array.from(iv);
    const encryptedArray = Array.from(new Uint8Array(encrypted));
    return JSON.stringify({
        iv: ivArray,
        data: encryptedArray
    });
}

// Decrypt message
async function decryptMessage(jsonStr) {
    if (!cryptoKey) return "🔒 Key Error";
    try {
        const raw = JSON.parse(jsonStr);
        const iv = new Uint8Array(raw.iv);
        const data = new Uint8Array(raw.data);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            data
        );

        const dec = new TextDecoder();
        return dec.decode(decrypted);
    } catch (e) {
        console.error("Decryption failed", e);
        return "⚠️ Failed to decrypt (Wrong Key?)";
    }
}
