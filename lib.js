import * as bigintCryptoUtils from './bigintCryptoUtils.js';

export async function generateRsaKeys(keySize) {
    const e = BigInt(65537);
    let p, q;
    let lambda;
    
    do {
        p = await bigintCryptoUtils.prime(keySize / 2);
        q = await bigintCryptoUtils.prime(keySize / 2);
        lambda = bigintCryptoUtils.lcm(p - 1n, q - 1n);
    } while (bigintCryptoUtils.gcd(e, lambda) !== 1n);

    return {
        n: p * q,
        e,
        d: bigintCryptoUtils.modInv(e, lambda)
    }
}

export function sign(m, d, n) {
    return bigintCryptoUtils.modPow(m, d, n);
}

export function decryptSignature(s, e, n) {
    return bigintCryptoUtils.modPow(s, e, n);
}

export function stringToHex(str) {
    let result = '';
    for (let i = 0; i < str.length; ++i) {
        result += (str.charCodeAt(i).toString(16)).slice(-4);
    }
    return '0x' + result;
}

export function stringFromHex(hex) {
    hex = hex.replace(/^0x/g, '')
    let result = '';
    for (let i = 0; i < hex.length; i += 2) {
        result += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    }
    return result;
}

export async function sha256(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map(x => x.toString(16).padStart(2,'0')).join('');
}
