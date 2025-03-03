/**
 * Shadowsocks Node.js Implementation
 * Main entry point for the library
 */

const ShadowsocksLocal = require('./local');
const { AEAD_METHODS } = require('./crypto/methods');
const { AEADEncryptor, AEADDecryptor } = require('./crypto/aead');
const { logger, setVerbose } = require('./utils/logger');

// Export public API
module.exports = {
  ShadowsocksLocal,
  AEAD_METHODS,
  AEADEncryptor,
  AEADDecryptor,
  logger,
  setVerbose
}; 