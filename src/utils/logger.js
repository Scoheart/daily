/**
 * Logger utility for Shadowsocks
 */

const winston = require('winston');

// Custom format for detailed logging
const detailedFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
  let msg = `${timestamp} [${level}]: ${message}`;
  
  // Add metadata if available
  if (Object.keys(metadata).length > 0) {
    msg += ` ${JSON.stringify(metadata)}`;
  }
  
  return msg;
});

// Create logger instance
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.metadata({ fillExcept: ['message', 'level', 'timestamp'] }),
    detailedFormat
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp({
          format: 'YYYY-MM-DD HH:mm:ss'
        }),
        winston.format.metadata({ fillExcept: ['message', 'level', 'timestamp'] }),
        detailedFormat
      )
    })
  ]
});

// Set log level based on verbosity
function setVerbose(verbose) {
  if (verbose) {
    logger.level = 'debug';
    logger.debug('Verbose logging enabled');
  } else {
    logger.level = 'info';
  }
}

module.exports = {
  logger,
  setVerbose
}; 