const crypto = require('crypto');
const usedAlgorithm = 'aes-256-cbc';

const encryptionKeyRaw = process.env.ENCRYPTION_KEY ? process.env.ENCRYPTION_KEY.trim() : undefined;
const IVRaw = process.env.ENCRYPTION_IV ? process.env.ENCRYPTION_IV.trim() : undefined;

const encryptionKey = encryptionKeyRaw ? encryptionKeyRaw.replace(/["']/g, '') : undefined; 
const IV = IVRaw ? IVRaw.replace(/["']/g, '') : undefined; 

const KEY_BUFFER = encryptionKey ? Buffer.from(encryptionKey.substring(0, 32), 'utf8') : undefined; 
const IV_BUFFER = IV ? Buffer.from(IV.substring(0, 16), 'utf8') : undefined; 

const encrypt = (text) => {
    try {
        const cipher = crypto.createCipheriv(usedAlgorithm, KEY_BUFFER, IV_BUFFER);
        let encrypted = cipher.update(text.toString(), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    } catch (e) {
        console.error("Błąd podczas szyfrowania:", e.message); 
        return null; 
    }
};

const decrypt = (encryptedText) => {
    if (!encryptedText || typeof encryptedText !== 'string' || encryptedText.length === 0) {
        return '';
    }
    try {
        const decipher = crypto.createDecipheriv(usedAlgorithm, KEY_BUFFER, IV_BUFFER);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        console.error("Błąd podczas deszyfrowania:", e.message);
        return 'Błąd deszyfrowania';
    }
};

module.exports = {
    encrypt,
    decrypt
};