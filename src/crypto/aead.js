/**
 * Implementation of AEAD encryption protocol for Shadowsocks
 */

const { Transform } = require('stream');
const crypto = require('crypto');
const { AEAD_METHODS, deriveKey, createAEADCipher } = require('./methods');

/**
 * AEAD Encryption Transform Stream
 */
class AEADEncryptor extends Transform {
  /**
   * Create a new AEAD encryptor
   * @param {string} method - Encryption method
   * @param {string} password - Password
   */
  constructor(method, password) {
    super();
    
    if (!AEAD_METHODS[method]) {
      throw new Error(`Unsupported method: ${method}`);
    }
    
    this.method = method;
    this.password = password;
    this.methodInfo = AEAD_METHODS[method];
    this.keySize = this.methodInfo.keySize;
    this.saltSize = this.methodInfo.saltSize;
    this.nonceSize = this.methodInfo.nonceSize;
    this.tagSize = this.methodInfo.tagSize;
    
    this.salt = null;
    this.key = null;
    this.nonce = Buffer.alloc(this.nonceSize, 0);
    this.cipher = null;
    
    this.isFirstChunk = true;
    this.chunkId = 0;
  }

  /**
   * Initialize encryption with a random salt
   */
  initializeEncryption() {
    // Generate random salt
    this.salt = crypto.randomBytes(this.saltSize);
    
    // Derive key from password and salt
    this.key = deriveKey(this.password, this.salt, this.keySize);
    
    // Reset nonce to all zeros
    this.nonce.fill(0);
    this.chunkId = 0;
  }

  /**
   * Update nonce for the next chunk
   */
  updateNonce() {
    // Increment chunk id as a LE unsigned 64-bit integer
    this.chunkId++;
    
    // Use little-endian format to store the chunk ID in nonce
    let n = this.chunkId;
    for (let i = 0; i < 12; i++) {
      if (i < 8) {
        this.nonce[i] = n & 0xff;
        n = n >> 8;
      } else {
        this.nonce[i] = 0;
      }
    }
  }

  /**
   * Encrypt a chunk of data
   * @param {Buffer} chunk - Data to encrypt
   * @param {string} encoding - Chunk encoding (ignored for Buffer)
   * @param {Function} callback - Callback when done
   */
  _transform(chunk, encoding, callback) {
    try {
      if (this.isFirstChunk) {
        // Initialize encryption for first chunk
        this.initializeEncryption();
        
        // Send salt as first part of the stream
        this.push(this.salt);
        
        this.isFirstChunk = false;
      }
      
      if (chunk.length === 0) {
        return callback();
      }
      
      // Step 1: Encrypt the length
      // Prepare length as a 2-byte value in network byte order (big-endian)
      const lengthBuf = Buffer.alloc(2);
      lengthBuf.writeUInt16BE(chunk.length, 0);
      
      // Create length cipher with current nonce
      const lengthCipher = createAEADCipher(this.method, this.key, this.nonce, true);
      const encryptedLength = lengthCipher.update(lengthBuf);
      lengthCipher.final();
      const lengthTag = lengthCipher.getAuthTag();
      
      // Step 2: Update nonce for payload
      this.updateNonce();
      
      // Step 3: Encrypt the payload
      const payloadCipher = createAEADCipher(this.method, this.key, this.nonce, true);
      const encryptedPayload = payloadCipher.update(chunk);
      payloadCipher.final();
      const payloadTag = payloadCipher.getAuthTag();
      
      // Step 4: Update nonce for next chunk
      this.updateNonce();
      
      // Step 5: Push encrypted data to output stream
      // Format: [encrypted length][length tag][encrypted payload][payload tag]
      this.push(Buffer.concat([
        encryptedLength, 
        lengthTag,
        encryptedPayload, 
        payloadTag
      ]));
      
      callback();
    } catch (err) {
      callback(err);
    }
  }
}

/**
 * AEAD Decryption Transform Stream
 */
class AEADDecryptor extends Transform {
  /**
   * Create a new AEAD decryptor
   * @param {string} method - Encryption method
   * @param {string} password - Password
   */
  constructor(method, password) {
    super();
    
    if (!AEAD_METHODS[method]) {
      throw new Error(`Unsupported method: ${method}`);
    }
    
    this.method = method;
    this.password = password;
    this.methodInfo = AEAD_METHODS[method];
    this.keySize = this.methodInfo.keySize;
    this.saltSize = this.methodInfo.saltSize;
    this.nonceSize = this.methodInfo.nonceSize;
    this.tagSize = this.methodInfo.tagSize;
    
    this.salt = null;
    this.key = null;
    this.nonce = Buffer.alloc(this.nonceSize, 0);
    this.decipher = null;
    
    this.isFirstChunk = true;
    this.chunkId = 0;
    
    // Buffer for incomplete data
    this.buffer = Buffer.alloc(0);
    
    // Current decryption state
    this.expectingLength = true;
    this.payloadLength = 0;
  }

  /**
   * Initialize decryption with received salt
   * @param {Buffer} salt - Salt received from remote
   */
  initializeDecryption(salt) {
    this.salt = salt;
    
    // Derive key from password and salt
    this.key = deriveKey(this.password, this.salt, this.keySize);
    
    // Reset nonce to all zeros
    this.nonce.fill(0);
    this.chunkId = 0;
  }

  /**
   * Update nonce for the next chunk
   */
  updateNonce() {
    // Increment chunk id as a LE unsigned 64-bit integer
    this.chunkId++;
    
    // Use little-endian format to store the chunk ID in nonce
    let n = this.chunkId;
    for (let i = 0; i < 12; i++) {
      if (i < 8) {
        this.nonce[i] = n & 0xff;
        n = n >> 8;
      } else {
        this.nonce[i] = 0;
      }
    }
  }

  /**
   * Decrypt a chunk of data
   * @param {Buffer} chunk - Data to decrypt
   * @param {string} encoding - Chunk encoding (ignored for Buffer)
   * @param {Function} callback - Callback when done
   */
  _transform(chunk, encoding, callback) {
    try {
      // Append new data to buffer
      this.buffer = Buffer.concat([this.buffer, chunk]);
      
      // Process initial salt
      if (this.isFirstChunk) {
        if (this.buffer.length < this.saltSize) {
          // Not enough data for salt, wait for more
          return callback();
        }
        
        // Extract salt and initialize decryption
        const salt = this.buffer.slice(0, this.saltSize);
        this.buffer = this.buffer.slice(this.saltSize);
        
        this.initializeDecryption(salt);
        this.isFirstChunk = false;
      }
      
      // Process data in a loop
      while (this.buffer.length > 0) {
        if (this.expectingLength) {
          // We're expecting encrypted length (2 bytes + tag)
          const lengthSize = 2 + this.tagSize;
          
          if (this.buffer.length < lengthSize) {
            // Not enough data for length, wait for more
            break;
          }
          
          // Decrypt length
          const encryptedLength = this.buffer.slice(0, 2);
          const lengthTag = this.buffer.slice(2, lengthSize);
          
          const lengthDecipher = createAEADCipher(this.method, this.key, this.nonce, false);
          
          try {
            lengthDecipher.setAuthTag(lengthTag);
            const lengthBuf = lengthDecipher.update(encryptedLength);
            lengthDecipher.final();
            
            // Extract payload length
            this.payloadLength = lengthBuf.readUInt16BE(0);
            
            // Update nonce for payload
            this.updateNonce();
            
            // Move to expect payload
            this.expectingLength = false;
            
            // Remove processed length data from buffer
            this.buffer = this.buffer.slice(lengthSize);
          } catch (err) {
            // Authentication failure
            return callback(new Error('AEAD authentication failed for length'));
          }
        } else {
          // We're expecting payload
          const payloadSize = this.payloadLength + this.tagSize;
          
          if (this.buffer.length < payloadSize) {
            // Not enough data for payload, wait for more
            break;
          }
          
          // Decrypt payload
          const encryptedPayload = this.buffer.slice(0, this.payloadLength);
          const payloadTag = this.buffer.slice(this.payloadLength, payloadSize);
          
          const payloadDecipher = createAEADCipher(this.method, this.key, this.nonce, false);
          
          try {
            payloadDecipher.setAuthTag(payloadTag);
            const payload = payloadDecipher.update(encryptedPayload);
            payloadDecipher.final();
            
            // Push decrypted payload
            this.push(payload);
            
            // Update nonce for next chunk
            this.updateNonce();
            
            // Move to expect length again
            this.expectingLength = true;
            
            // Remove processed payload data from buffer
            this.buffer = this.buffer.slice(payloadSize);
          } catch (err) {
            // Authentication failure
            return callback(new Error('AEAD authentication failed for payload'));
          }
        }
      }
      
      callback();
    } catch (err) {
      callback(err);
    }
  }
}

module.exports = {
  AEADEncryptor,
  AEADDecryptor
}; 