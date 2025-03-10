const net = require('net');

// SOCKS5 服务器监听端口
const PORT = 1080;
const HOST = '0.0.0.0';

// SOCKS5 响应码
const SOCKS5_REPLY = {
  SUCCESS: 0x00,
  GENERAL_FAILURE: 0x01,
  CONNECTION_NOT_ALLOWED: 0x02,
  NETWORK_UNREACHABLE: 0x03,
  HOST_UNREACHABLE: 0x04,
  CONNECTION_REFUSED: 0x05,
  TTL_EXPIRED: 0x06,
  COMMAND_NOT_SUPPORTED: 0x07,
  ADDRESS_TYPE_NOT_SUPPORTED: 0x08,
};

// 创建 SOCKS5 服务器
const server = net.createServer((clientSocket) => {
  console.log('Client connected');

  clientSocket.once('data', (data) => {
    console.log('[log] data', data);

    // 解析 SOCKS5 认证请求
    if (data[0] !== 0x05) {
      console.log('Not a SOCKS5 request');
      clientSocket.end();
      return;
    }

    const numMethods = data[1];
    const methods = data.slice(2, 2 + numMethods);

    // 只支持无认证 (0x00)
    if (!methods.includes(0x00)) {
      console.log('Client requires authentication, rejecting');
      clientSocket.write(Buffer.from([0x05, 0xff]));
      clientSocket.end();
      return;
    }

    // 发送认证响应 (无需认证)
    clientSocket.write(Buffer.from([0x05, 0x00]));

    // 监听代理请求
    clientSocket.once('data', (request) => {
      if (request[0] !== 0x05) {
        console.log('Invalid request version');
        clientSocket.end();
        return;
      }

      const cmd = request[1];
      const atyp = request[3];

      // 只支持 CONNECT 命令
      if (cmd !== 0x01) {
        console.log('Unsupported command');
        clientSocket.write(
          Buffer.from([
            0x05,
            SOCKS5_REPLY.COMMAND_NOT_SUPPORTED,
            0x00,
            0x01,
            0,
            0,
            0,
            0,
            0,
            0,
          ])
        );
        clientSocket.end();
        return;
      }

      let address;
      let port;

      // 解析目标地址
      if (atyp === 0x01) {
        // IPv4 地址
        address = request.slice(4, 8).join('.');
        port = request.readUInt16BE(8);
      } else if (atyp === 0x03) {
        // 域名
        const domainLength = request[4];
        address = request.slice(5, 5 + domainLength).toString();
        port = request.readUInt16BE(5 + domainLength);
      } else if (atyp === 0x04) {
        // IPv6 地址（不支持）
        console.log('IPv6 not supported');
        clientSocket.write(
          Buffer.from([
            0x05,
            SOCKS5_REPLY.ADDRESS_TYPE_NOT_SUPPORTED,
            0x00,
            0x01,
            0,
            0,
            0,
            0,
            0,
            0,
          ])
        );
        clientSocket.end();
        return;
      } else {
        console.log('Unknown address type');
        clientSocket.end();
        return;
      }

      console.log(`Connecting to ${address}:${port}`);

      // 连接目标服务器
      const remoteSocket = net.createConnection(
        { host: address, port: port },
        () => {
          // 连接成功，回复客户端
          const response = Buffer.from([
            0x05,
            SOCKS5_REPLY.SUCCESS,
            0x00,
            0x01,
            0,
            0,
            0,
            0,
            0,
            0,
          ]);
          clientSocket.write(response);

          // 建立数据转发
          clientSocket.pipe(remoteSocket);
          remoteSocket.pipe(clientSocket);
        }
      );

      remoteSocket.on('error', (err) => {
        console.log(`Connection failed: ${err.message}`);
        clientSocket.write(
          Buffer.from([
            0x05,
            SOCKS5_REPLY.GENERAL_FAILURE,
            0x00,
            0x01,
            0,
            0,
            0,
            0,
            0,
            0,
          ])
        );
        clientSocket.end();
      });
    });
  });

  clientSocket.on('error', (err) => {
    console.log(`Client socket error: ${err.message}`);
  });

  clientSocket.on('end', () => {
    console.log('Client disconnected');
  });
});

// 启动服务器
server.listen(PORT, HOST, () => {
  console.log(`SOCKS5 Proxy Server running on ${HOST}:${PORT}`);
});


go-shadowsocks2 -s 'ss://AEAD_CHACHA20_POLY130:12345678@:8488' -verbose