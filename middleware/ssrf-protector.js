const url = require('url');
const dns = require('dns/promises');

const PRIVATE_RANGES = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[0-1])\./, 
    /^192\.168\./,    
    /^127\./,         
    /^169\.254\./     
];


const ALLOWED_HOSTS = new Set([
    'www.google.com',
    'google.com', 
    'www.recaptcha.net', 
    'recaptcha.net',
    'www.swapi.dev',
    'swapi.dev',
]);


function isDangerousIP(ip) {
    if (!ip || ip.includes(':')) {
        return false; 
    }
    return PRIVATE_RANGES.some(range => range.test(ip));
}


async function safeFetchResource(targetUrl, fetchMethod) {
    let parsedUrl;

    try {
        parsedUrl = new url.URL(targetUrl);
    } catch (e) {
        throw new Error("Nieprawidłowy format URL.");
    }

    const { hostname, protocol } = parsedUrl;

    if (protocol !== 'http:' && protocol !== 'https:') {
        throw new Error("Niedozwolony protokół (dozwolone tylko HTTP/HTTPS).");
    }
 
    if (!ALLOWED_HOSTS.has(hostname)) {
        console.warn(`[SSRF BLOCKED] Host ${hostname} nie znajduje się na liście dozwolonych domen (whitelist).`);
        throw new Error(`[A10:2021 SSRF] Zablokowano dostęp do nieautoryzowanej domeny.`);
    }

    try {
        const { address } = await dns.lookup(hostname); 
        const targetIp = address;
        if (isDangerousIP(targetIp)) {
            console.warn(`[SSRF BLOCKED] Access attempt to restricted IP: ${targetIp} from host: ${hostname}`);
            throw new Error(`[A10:2021 SSRF] Zablokowano dostęp do prywatnego/zastrzeżonego adresu IP: ${targetIp}`);
        }

    } catch (e) {
        if (e.code === 'ENOTFOUND') {
            throw new Error(`Nie można rozwiązać nazwy hosta: ${hostname}`);
        }
        throw e; 
    }

    try {
        const response = await fetchMethod(targetUrl, {
            timeout: 5000,
            size: 1024 * 1024,
            redirect: 'manual', 
        });

        if (response.status >= 300 && response.status < 400 && response.headers.has('Location')) {
            console.warn(`[SSRF ALERT] Manual redirect detected for: ${targetUrl}`);
            throw new Error("[A10:2021 SSRF] Blokada: Wykryto próbę przekierowania na inny URL.");
        }
        return response.buffer();  
    } catch (e) {
        throw new Error(`Błąd pobierania zasobu (Sieć/HTTP): ${e.message}`);
    }
}

module.exports = { safeFetchResource };