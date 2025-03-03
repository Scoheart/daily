/**
 * Shadowsocks local client implementation (ss-local)
 * 
 * This creates a SOCKS5 proxy server that tunnels traffic through a Shadowsocks server
 */

const net = require('net');
const { SocksClient, SocksCommand } = require('socks');
const { AEADEncryptor, AEADDecryptor } = require('./crypto/aead');
const { AEAD_METHODS } = require('./crypto/methods');
const { logger } = require('./utils/logger');

/**
 * Shadowsocks Local Client class
 */
class ShadowsocksLocal {
  /**
   * Create a new Shadowsocks local client
   * @param {Object} config - Configuration options
   * @param {string} config.serverAddr - Remote server address
   * @param {number} config.serverPort - Remote server port
   * @param {string} config.password - Password for encryption
   * @param {string} config.method - Encryption method
   * @param {number} config.localPort - Local SOCKS5 port (default: 1080)
   * @param {number} config.timeout - Connection timeout in seconds (default: 60)
   */
  constructor(config) {
    this.serverAddr = config.serverAddr;
    this.serverPort = config.serverPort;
    this.password = config.password;
    this.method = config.method;
    this.localPort = config.localPort || 1080;
    this.timeout = (config.timeout || 60) * 1000; // Convert to milliseconds
    
    // Validate encryption method
    if (!AEAD_METHODS[this.method]) {
      throw new Error(`Unsupported encryption method: ${this.method}`);
    }
    
    this.server = null;
  }
  
  /**
   * Start the local SOCKS5 server
   * @returns {Promise} Promise that resolves when server is started
   */
  start() {
    return new Promise((resolve, reject) => {
      try {
        // Create TCP server for SOCKS5
        this.server = net.createServer((clientConn) => {
          this.handleSocksClient(clientConn);
        });
        
        // Handle server errors
        this.server.on('error', (err) => {
          logger.error(`Local server error: ${err.message}`);
          reject(err);
        });
        
        // Start listening
        this.server.listen(this.localPort, () => {
          logger.info(`Shadowsocks local client listening on 127.0.0.1:${this.localPort}`);
          logger.info(`Remote server: ${this.serverAddr}:${this.serverPort}`);
          logger.info(`Encryption method: ${this.method}`);
          resolve();
        });
      } catch (err) {
        reject(err);
      }
    });
  }
  
  /**
   * Stop the local SOCKS5 server
   * @returns {Promise} Promise that resolves when server is stopped
   */
  stop() {
    return new Promise((resolve, reject) => {
      if (!this.server) {
        resolve();
        return;
      }
      
      this.server.close((err) => {
        if (err) {
          reject(err);
        } else {
          logger.info('Shadowsocks local client stopped');
          resolve();
        }
      });
    });
  }
  
  /**
   * Handle a new SOCKS5 client connection
   * @param {net.Socket} clientConn - Client connection socket
   */
  handleSocksClient(clientConn) {
    clientConn.on('error', (err) => {
      logger.debug(`Client connection error: ${err.message}`);
      clientConn.destroy();
    });
    
    // Handle the SOCKS5 handshake
    this.handleSocksHandshake(clientConn);
  }
  
  /**
   * Handle SOCKS5 handshake
   * @param {net.Socket} clientConn - Client connection socket
   */
  handleSocksHandshake(clientConn) {
    let handshakeBuffer = Buffer.alloc(0);
    
    const handshakeHandler = (data) => {
      // Accumulate data
      handshakeBuffer = Buffer.concat([handshakeBuffer, data]);
      
      // Check if we have at least 2 bytes for the SOCKS5 version and auth methods
      if (handshakeBuffer.length < 2) {
        return;
      }
      
      // Check SOCKS5 version
      if (handshakeBuffer[0] !== 0x05) {
        logger.error('Invalid SOCKS version');
        clientConn.destroy();
        return;
      }
      
      // Get number of auth methods
      const numMethods = handshakeBuffer[1];
      
      // Check if we have the complete handshake
      if (handshakeBuffer.length < 2 + numMethods) {
        return;
      }
      
      // We've completed the handshake - remove this handler
      clientConn.removeListener('data', handshakeHandler);
      
      // Respond with "no authentication required"
      clientConn.write(Buffer.from([0x05, 0x00]));
      
      // Move to request handling
      this.handleSocksRequest(clientConn);
    };
    
    clientConn.on('data', handshakeHandler);
  }
  
  /**
   * Handle SOCKS5 request
   * @param {net.Socket} clientConn - Client connection socket
   */
  handleSocksRequest(clientConn) {
    let requestBuffer = Buffer.alloc(0);
    
    const requestHandler = (data) => {
      // Accumulate data
      requestBuffer = Buffer.concat([requestBuffer, data]);
      
      // SOCKS5 request format:
      // +----+-----+-------+------+----------+----------+
      // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
      // +----+-----+-------+------+----------+----------+
      // | 1  |  1  | X'00' |  1   | Variable |    2     |
      // +----+-----+-------+------+----------+----------+
      
      // Minimum length (version + command + reserved + address type)
      if (requestBuffer.length < 4) {
        return;
      }
      
      // Check version and reserved byte
      if (requestBuffer[0] !== 0x05 || requestBuffer[2] !== 0x00) {
        logger.error('Invalid SOCKS5 request');
        clientConn.destroy();
        return;
      }
      
      // Get command (only CONNECT = 0x01 is supported)
      const cmd = requestBuffer[1];
      if (cmd !== 0x01) {
        logger.error(`Unsupported SOCKS5 command: ${cmd}`);
        // Send command not supported reply
        clientConn.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        clientConn.destroy();
        return;
      }
      
      // Get address type
      const addrType = requestBuffer[3];
      
      let addrLength = 0;
      switch (addrType) {
        case 0x01: // IPv4
          addrLength = 4;
          break;
        case 0x03: // Domain name
          // First byte is the length of the domain name
          if (requestBuffer.length < 5) {
            return; // Need more data
          }
          addrLength = requestBuffer[4] + 1; // +1 for length byte
          break;
        case 0x04: // IPv6
          addrLength = 16;
          break;
        default:
          logger.error(`Unsupported address type: ${addrType}`);
          // Send address type not supported reply
          clientConn.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          clientConn.destroy();
          return;
      }
      
      // Check if we have the complete request (header + address + port)
      if (requestBuffer.length < 4 + addrLength + 2) {
        return; // Need more data
      }
      
      // We have a complete request - remove this handler
      clientConn.removeListener('data', requestHandler);
      
      // Extract the address and port
      let dstAddr, dstPort;
      
      switch (addrType) {
        case 0x01: // IPv4
          dstAddr = Array.from(requestBuffer.slice(4, 8)).join('.');
          break;
        case 0x03: // Domain name
          const domainLength = requestBuffer[4];
          dstAddr = requestBuffer.slice(5, 5 + domainLength).toString();
          break;
        case 0x04: // IPv6
          // Format IPv6 address
          const ipv6 = [];
          for (let i = 0; i < 16; i += 2) {
            ipv6.push(requestBuffer.readUInt16BE(4 + i).toString(16));
          }
          dstAddr = ipv6.join(':');
          break;
      }
      
      // Get port (network byte order)
      const portOffset = 4 + addrLength;
      dstPort = requestBuffer.readUInt16BE(portOffset);
      
      logger.debug(`SOCKS5 request for ${dstAddr}:${dstPort}`);
      
      // Establish connection to the Shadowsocks server with target address
      // The format is:
      // [Address Type][Destination Address][Destination Port]
      this.connectToServer(clientConn, requestBuffer.slice(3, portOffset + 2));
    };
    
    clientConn.on('data', requestHandler);
  }
  
  /**
   * Connect to Shadowsocks server and relay the connection
   * @param {net.Socket} clientConn - Client connection socket
   * @param {Buffer} targetAddr - Target address buffer (includes address type, address, and port)
   */
  connectToServer(clientConn, targetAddr) {
    // Connect to remote Shadowsocks server
    const serverConn = net.createConnection({
      host: this.serverAddr,
      port: this.serverPort,
      timeout: this.timeout
    });
    
    serverConn.once('error', (err) => {
      logger.error(`Server connection error: ${err.message}`);
      
      // Send failure reply to the client
      if (clientConn.writable) {
        // Reply with general failure
        clientConn.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        clientConn.destroy();
      }
      
      serverConn.destroy();
    });
    
    serverConn.once('timeout', () => {
      logger.error('Server connection timeout');
      serverConn.destroy();
      if (clientConn.writable) {
        clientConn.destroy();
      }
    });
    
    serverConn.once('connect', () => {
      logger.debug('Connected to Shadowsocks server');
      
      // Create encryption streams
      const encryptor = new AEADEncryptor(this.method, this.password);
      const decryptor = new AEADDecryptor(this.method, this.password);
      
      // Error handlers - prevent unhandled errors from crashing the application
      encryptor.on('error', (err) => {
        logger.error(`Encryption error: ${err.message}`);
        clientConn.destroy();
        serverConn.destroy();
      });
      
      decryptor.on('error', (err) => {
        logger.error(`Decryption error: ${err.message}`);
        clientConn.destroy();
        serverConn.destroy();
      });
      
      // Send target address to server through the encrypted connection
      encryptor.write(targetAddr);
      
      // Send successful reply to the client (address and port don't matter, client ignores them)
      clientConn.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      
      // Set up piping between client and server
      clientConn.pipe(encryptor).pipe(serverConn);
      serverConn.pipe(decryptor).pipe(clientConn);
      
      // Handle connection close
      clientConn.on('close', (hadError) => {
        logger.debug(`Client connection closed${hadError ? ' with error' : ''}`);
        if (serverConn.writable) {
          serverConn.destroy();
        }
      });
      
      serverConn.on('close', (hadError) => {
        logger.debug(`Server connection closed${hadError ? ' with error' : ''}`);
        if (clientConn.writable) {
          clientConn.destroy();
        }
      });
    });
  }
}

module.exports = ShadowsocksLocal; 