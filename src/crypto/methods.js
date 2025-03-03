/**
 * Supported encryption methods for Shadowsocks
 */

const crypto = require('crypto');

// AEAD ciphers
const AEAD_METHODS = {
  'aes-128-gcm': {
    keySize: 16,
    saltSize: 16,
    nonceSize: 12,
    tagSize: 16,
  },
  'aes-256-gcm': {
    keySize: 32,
    saltSize: 32,
    nonceSize: 12,
    tagSize: 16,
  },
  'chacha20-ietf-poly1305': {
    keySize: 32,
    saltSize: 32,
    nonceSize: 12,
    tagSize: 16,
  },
};

/**
 * EVP_BytesToKey implementation from OpenSSL
 * This matches the key derivation in shadowsocks-libev
 * @param {string} password 
 * @param {number} keyLen 
 * @returns {Buffer} derived key
 */
function EVP_BytesToKey(password, keyLen) {
  const md5Rounds = Math.ceil(keyLen / 16);
  const result = Buffer.alloc(md5Rounds * 16);
  
  const passwordBuffer = Buffer.from(password);
  
  let lastRound = Buffer.alloc(0);
  for (let i = 0; i < md5Rounds; i++) {
    const md5 = crypto.createHash('md5');
    
    if (i > 0) {
      md5.update(lastRound);
    }
    
    md5.update(passwordBuffer);
    
    lastRound = md5.digest();
    lastRound.copy(result, i * 16);
  }
  
  return result.slice(0, keyLen);
}

/**
 * Derives key from password and salt using HKDF
 * @param {string} password 
 * @param {Buffer} salt 
 * @param {number} keySize 
 * @returns {Buffer} derived key
 */
function deriveKey(password, salt, keySize) {
  const passwordKey = EVP_BytesToKey(password, keySize);
  
  // Use HKDF with SHA1 to derive the subkey, matching shadowsocks-libev
  return crypto.hkdfSync('sha1', passwordKey, salt, Buffer.from('ss-subkey'), keySize);
}

/**
 * Creates AEAD cipher using specified method and key
 * @param {string} method 
 * @param {Buffer} key 
 * @param {Buffer} nonce 
 * @param {boolean} isEncrypt 
 * @returns {crypto.CipherGCM|crypto.DecipherGCM} cipher or decipher
 */
function createAEADCipher(method, key, nonce, isEncrypt) {
  let algorithm;
  
  if (method === 'chacha20-ietf-poly1305') {
    algorithm = 'chacha20-poly1305'; // Node.js uses different name
  } else {
    algorithm = method;
  }
  
  if (isEncrypt) {
    return crypto.createCipheriv(algorithm, key, nonce, { authTagLength: AEAD_METHODS[method].tagSize });
  } else {
    return crypto.createDecipheriv(algorithm, key, nonce, { authTagLength: AEAD_METHODS[method].tagSize });
  }
}

/**
 * AEAD encrypt a chunk of data
 * @param {Buffer} data 
 * @param {crypto.CipherGCM} cipher 
 * @returns {Buffer} encrypted data with authentication tag
 */
function encryptAEAD(data, cipher) {
  const ciphertext = cipher.update(data);
  const final = cipher.final();
  const tag = cipher.getAuthTag();
  
  return Buffer.concat([
    Buffer.alloc(2, 0), // Two bytes for length
    ciphertext,
    final,
    tag
  ]);
}

/**
 * AEAD decrypt a chunk of data
 * @param {Buffer} data 
 * @param {crypto.DecipherGCM} decipher 
 * @param {number} tagSize 
 * @returns {Buffer|null} decrypted data or null if verification failed
 */
function decryptAEAD(data, decipher, tagSize) {
  try {
    const tag = data.slice(data.length - tagSize);
    const ciphertext = data.slice(0, data.length - tagSize);
    
    decipher.setAuthTag(tag);
    const plaintext = decipher.update(ciphertext);
    const final = decipher.final();
    
    return Buffer.concat([plaintext, final]);
  } catch (err) {
    return null; // Authentication failed
  }
}

module.exports = {
  AEAD_METHODS,
  deriveKey,
  createAEADCipher,
  encryptAEAD,
  decryptAEAD,
  EVP_BytesToKey
}; 