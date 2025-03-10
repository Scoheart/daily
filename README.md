# Shadowsocks Node

A Node.js implementation of the Shadowsocks protocol, focusing on replicating the functionality of shadowsocks-libev's ss-local component.

## Features

- SOCKS5 proxy implementing the Shadowsocks protocol
- Support for various encryption methods
- Command-line interface similar to shadowsocks-libev

## Installation

```bash
npm install
```

## Usage

Start the local client:

```bash
npm run start:local -- -s [server_address] -p [server_port] -k [password] -m [method] -l [local_port]
```

Or with direct node command:

```bash
node src/bin/ss-local.js -s 127.0.0.1 -p 8388 -k "your-password" -m aes-256-gcm -l 1080


node src/bin/ss-local.js -s 52.77.225.164 -p 8388 -k "12345678" -m aes-256-gcm -l 8088
node src/bin/ss-local.js -s 52.77.225.164 -p 8388 -k "12345678" -m aes-256-gcm -l 1080
```

curl -x socks5://127.0.0.1:1080 -v http://ip.sb
curl -x socks5://127.0.0.1:8088 -v http://ip.sb

curl -x socks5://127.0.0.1:7890 -v http://ip.sb

curl --proxy socks5://127.0.0.1:1080 -v http://ip.sb

curl --proxy socks5://127.0.0.1:1080 -v https://scoheart.vercel.app/

curl --proxy socks5://127.0.0.1:1080 -v https://github.com/Scoheart/scoheart-notes

curl --proxy socks5://127.0.0.1:1080 -v https://www.youtube.com/watch?v=SLBOebb4OCw

### Command-line options

- `-s, --server-addr`: Server address
- `-p, --server-port`: Server port
- `-l, --local-port`: Local port (defaults to 1080)
- `-k, --password`: Password for encryption
- `-m, --method`: Encryption method (e.g., aes-256-gcm, chacha20-ietf-poly1305)
- `-t, --timeout`: Connection timeout in seconds (defaults to 60)
- `-v, --verbose`: Verbose mode

## Supported Encryption Methods

- aes-256-gcm
- aes-128-gcm
- chacha20-ietf-poly1305
- And more...

## License

MIT 