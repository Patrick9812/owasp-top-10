const crypto = require('crypto');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; 
const ALGORITHM = 'aes-256-gcm'; 
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

if (!ENCRYPTION_KEY) {
    throw new Error("Błąd konfiguracji: Wymagana zmienna środowiskowa ENCRYPTION_KEY.");
}

const KEY_BUFFER = Buffer.from(ENCRYPTION_KEY.trim().substring(0, 32), 'hex');

const encrypt = (text) => {
    try {
        if (!text) return '';
        
        const iv = crypto.randomBytes(IV_LENGTH); 
        const cipher = crypto.createCipheriv(ALGORITHM, KEY_BUFFER, iv);

        let encrypted = cipher.update(text.toString(), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();

        return iv.toString('hex') + ':' + encrypted + ':' + authTag.toString('hex');
    } catch (e) {
        console.error("Błąd podczas szyfrowania GCM:", e.message); 
        return null; 
    }
};

// A8 Software and Data Integrity Failures
const decrypt = (encryptedText) => {
    if (!encryptedText || typeof encryptedText !== 'string' || encryptedText.length === 0) {
        return '';
    }
    
    const parts = encryptedText.split(':');
    
    if (parts.length !== 3) {
        console.error("Błąd integralności (A08): Nieprawidłowy format zaszyfrowanych danych.");
        throw new Error('Błąd integralności danych: format niepoprawny.');
    }
    
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const authTag = Buffer.from(parts[2], 'hex');

    if (iv.length !== IV_LENGTH || authTag.length !== AUTH_TAG_LENGTH) {
        console.error("Błąd integralności (A08): Nieprawidłowa długość IV/Tag.");
        throw new Error('Błąd integralności danych: nieprawidłowa długość.');
    }

    try {
        const decipher = crypto.createDecipheriv(ALGORITHM, KEY_BUFFER, iv);
        decipher.setAuthTag(authTag);
        
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (e) {
        console.error("Błąd weryfikacji integralności danych (A08):", e.message);
        throw new Error('Naruszenie integralności (A08): Dane zostały zmienione.');
    }
};

module.exports = {
    encrypt,
    decrypt
};