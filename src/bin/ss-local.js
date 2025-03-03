#!/usr/bin/env node

/**
 * Command-line interface for the Shadowsocks local client (ss-local)
 */

const { program } = require('commander');
const ShadowsocksLocal = require('../local');
const { AEAD_METHODS } = require('../crypto/methods');
const { logger, setVerbose } = require('../utils/logger');

// Setup command-line interface
program
  .name('ss-local')
  .description('Shadowsocks local client (SOCKS5 proxy)')
  .version('1.0.0')
  .option('-s, --server-addr <address>', 'Server address')
  .option('-p, --server-port <port>', 'Server port', parseInt)
  .option('-l, --local-port <port>', 'Local port', parseInt, 1080)
  .option('-k, --password <password>', 'Password')
  .option('-m, --method <method>', 'Encryption method', 'aes-256-gcm')
  .option('-t, --timeout <seconds>', 'Connection timeout in seconds', parseInt, 60)
  .option('-v, --verbose', 'Verbose mode')
  .option('--debug', 'Enable debug logging (same as -v)')
  .option('--list-methods', 'List available encryption methods')
  .parse(process.argv);

// Get options
const options = program.opts();

// Show available methods if requested
const showMethods = () => {
  console.log('Available encryption methods:');
  Object.keys(AEAD_METHODS).forEach(method => {
    console.log(`  ${method}`);
  });
  process.exit(0);
};

// Process command line options
if (options.listMethods) {
  showMethods();
}

// Validate options
if (!options.serverAddr) {
  logger.error('Server address (-s, --server-addr) is required');
  process.exit(1);
}

if (!options.serverPort) {
  logger.error('Server port (-p, --server-port) is required');
  process.exit(1);
}

if (!options.password) {
  logger.error('Password (-k, --password) is required');
  process.exit(1);
}

if (!AEAD_METHODS[options.method]) {
  logger.error(`Unsupported encryption method: ${options.method}`);
  logger.info(`Supported methods: ${Object.keys(AEAD_METHODS).join(', ')}`);
  process.exit(1);
}

// Set verbose mode
setVerbose(options.verbose || options.debug);

// Log configuration
logger.info(`Configuration: 
  - Server: ${options.serverAddr}:${options.serverPort}
  - Local port: ${options.localPort}
  - Method: ${options.method}
  - Timeout: ${options.timeout}s
  - Debug mode: ${(options.verbose || options.debug) ? 'on' : 'off'}`);

// Create Shadowsocks local client
const ssLocal = new ShadowsocksLocal({
  serverAddr: options.serverAddr,
  serverPort: options.serverPort,
  localPort: options.localPort,
  password: options.password,
  method: options.method,
  timeout: options.timeout
});

// Handle process signals for clean shutdown
process.on('SIGINT', async () => {
  logger.info('Received SIGINT, shutting down...');
  await ssLocal.stop();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM, shutting down...');
  await ssLocal.stop();
  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error(`Uncaught exception: ${err.message}`);
  logger.error(err.stack);
  process.exit(1);
});

// Start the server
ssLocal.start()
  .then(() => {
    logger.info(`SOCKS5 proxy listening at 127.0.0.1:${options.localPort}`);
    logger.info('Press Ctrl+C to stop');
  })
  .catch((err) => {
    logger.error(`Failed to start server: ${err.message}`);
    process.exit(1);
  }); 