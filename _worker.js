import { connect } from 'cloudflare:sockets';

let proxyIP = '210.61.97.241:81';  // proxyIP
let yourUUID = '93bf61d9-3796-44c2-9b3a-49210ece2585';  // UUID

// addssl网页渲染函数
function renderHtml() {
  return `
<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8">
  <title>自动添加 SSL 证书</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * {
      box-sizing: border-box;
    }
    body {
      font-family: "Segoe UI", "PingFang SC", sans-serif;
      background: #f0f2f5;
      margin: 0;
      padding: 0;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
    }
    .container {
      width: 100%;
      max-width: 480px;
      background: #fff;
      padding: 28px 24px;
      border-radius: 12px;
      box-shadow: 0 6px 20px rgba(0,0,0,0.08);
    }
    h2 {
      text-align: center;
      margin-bottom: 24px;
      color: #0078d7;
      font-weight: 600;
      font-size: 22px;
    }
    .form-group {
      margin-bottom: 18px;
    }
    label {
      font-size: 14px;
      font-weight: 500;
      margin-bottom: 6px;
      display: block;
      color: #333;
    }
    input, select {
      width: 100%;
      padding: 12px;
      font-size: 15px;
      border: 1px solid #ccc;
      border-radius: 8px;
      background: #f9f9f9;
      box-shadow: inset 0 1px 2px rgba(0,0,0,0.05);
      transition: all 0.2s ease;
    }
    input:focus, select:focus {
      outline: none;
      border-color: #0078d7;
      background: #fff;
      box-shadow: 0 0 0 2px rgba(0,120,215,0.2);
    }
    button {
      width: 100%;
      padding: 12px;
      background: #0078d7;
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: bold;
      cursor: pointer;
      transition: background 0.3s ease;
    }
    button:hover {
      background: #005fa3;
    }
    .message {
      margin-top: 20px;
      text-align: center;
      font-weight: bold;
      font-size: 15px;
      display: none;
    }
    @media (max-width: 600px) {
      .container {
        margin: 20px;
        padding: 20px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <h2>自动添加 SSL 证书</h2>
    <div class="form-group">
      <label for="custom-domain">自定义域名</label>
      <input type="text" id="custom-domain" placeholder="例如：example.com">
    </div>
    <div class="form-group">
      <label for="email">Cloudflare 邮箱</label>
      <input type="email" id="email" placeholder="你的 Cloudflare 邮箱">
    </div>
    <div class="form-group">
      <label for="zone-id">Zone ID</label>
      <input type="text" id="zone-id" placeholder="你的 Zone ID">
    </div>
    <div class="form-group">
      <label for="api-key">API Key</label>
      <input type="text" id="api-key" placeholder="你的 API Key">
    </div>
    <div class="form-group">
      <label for="ca-select">证书颁发机构</label>
      <select id="ca-select">
        <option value="ssl_com">SSL.com</option>
        <option value="lets_encrypt">Let's Encrypt</option>
        <option value="google">Google</option>
        <option value="sectigo">Sectigo</option>
      </select>
    </div>
    <button id="add-ssl-btn">添加 SSL 证书</button>
    <div class="message" id="message"></div>
  </div>

  <script>
    const inputs = document.querySelectorAll('input, select');
    const messageBox = document.getElementById('message');

    inputs.forEach(input => {
      input.addEventListener('input', () => {
        messageBox.style.display = 'none';
      });
    });

    document.getElementById('add-ssl-btn').addEventListener('click', async () => {
      const email = document.getElementById('email').value.trim();
      const zoneId = document.getElementById('zone-id').value.trim();
      const apikey = document.getElementById('api-key').value.trim();
      const caSelect = document.getElementById('ca-select').value;
      const customDomain = document.getElementById('custom-domain').value.trim();

      if (!email || !zoneId || !apikey) {
        messageBox.textContent = '请填写所有必填项';
        messageBox.style.color = 'red';
        messageBox.style.display = 'block';
        return;
      }

      try {
        const response = await fetch('/api/add-ssl', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: email,
            zoneId: zoneId,
            apikey: apikey,
            enabled: true,
            ca: caSelect,
            customDomain: customDomain || null
          })
        });

        const result = await response.json();
        if (result.success) {
          messageBox.textContent = '✅ SSL证书添加成功！';
          messageBox.style.color = 'green';
        } else {
          messageBox.textContent = '❌ 添加失败：' + JSON.stringify(result.errors);
          messageBox.style.color = 'red';
        }
        messageBox.style.display = 'block';
      } catch (err) {
        messageBox.textContent = '❌ 请求错误：' + err.message;
        messageBox.style.color = 'red';
        messageBox.style.display = 'block';
      }
    });
  </script>
</body>
</html>
`;
}

// addssl API处理函数
async function handleApiRequest(request) {
  try {
    const body = await request.json();
    const { email, zoneId, apikey, enabled = true, ca = "ssl_com", customDomain = null } = body;

    if (!email || !zoneId || !apikey) {
      return jsonResponse({ success: false, errors: ['邮箱、区域ID和API密钥都是必需的'] }, 400);
    }

    const validCAs = ["ssl_com", "lets_encrypt", "google", "sectigo"];
    const caToUse = validCAs.includes(ca) ? ca : "ssl_com";

    const payload = {
      enabled: enabled,
      certificate_authority: caToUse
    };

    if (customDomain) {
      payload.hostname = customDomain;
    }

    const response = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/ssl/universal/settings`, {
      method: 'PATCH',
      headers: {
        'X-Auth-Email': email,
        'X-Auth-Key': apikey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const result = await response.json();
    return jsonResponse(result);
  } catch (error) {
    return jsonResponse({ success: false, errors: [{ message: `请求失败: ${error.message || '未知错误'}` }] }, 500);
  }
}

// JSON响应辅助函数
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}

function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}`;
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try { 
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null }; 
    } catch (error) { 
        return { error }; 
    }
}

function closeSocketQuietly(socket) { 
    try { 
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close(); 
        }
    } catch (error) {} 
}

function isSpeedTestSite(hostname) {
    const speedTestDomains = ['speedtest.net','fast.com','speedtest.cn','speed.cloudflare.com','ovo.speedtestcustom.com'];
    if (speedTestDomains.includes(hostname)) {
        return true;
    }
    for (const domain of speedTestDomains) {
        if (hostname.endsWith('.' + domain) || hostname === domain) {
            return true;
        }
    }
    return false;
}

function parseProxyAddress(proxyStr) {
    if (!proxyStr) return null;
    proxyStr = proxyStr.trim();
    if (proxyStr.startsWith('socks://') || proxyStr.startsWith('socks5://')) {
        const urlStr = proxyStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            return {
                type: 'socks5',
                host: url.hostname,
                port: parseInt(url.port) || 1080,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    if (proxyStr.startsWith('http://') || proxyStr.startsWith('https://')) {
        try {
            const url = new URL(proxyStr);
            return {
                type: 'http',
                host: url.hostname,
                port: parseInt(url.port) || (proxyStr.startsWith('https://') ? 443 : 80),
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    if (proxyStr.startsWith('[')) {
        const closeBracket = proxyStr.indexOf(']');
        if (closeBracket > 0) {
            const host = proxyStr.substring(1, closeBracket);
            const rest = proxyStr.substring(closeBracket + 1);
            if (rest.startsWith(':')) {
                const port = parseInt(rest.substring(1), 10);
                if (!isNaN(port) && port > 0 && port <= 65535) {
                    return { type: 'direct', host, port };
                }
            }
            return { type: 'direct', host, port: 443 };
        }
    }
    
    const lastColonIndex = proxyStr.lastIndexOf(':');
    
    if (lastColonIndex > 0) {
        const host = proxyStr.substring(0, lastColonIndex);
        const portStr = proxyStr.substring(lastColonIndex + 1);
        const port = parseInt(portStr, 10);
        
        if (!isNaN(port) && port > 0 && port <= 65535) {
            return { type: 'direct', host, port };
        }
    }
    
    return { type: 'direct', host: proxyStr, port: 443 };
}

export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const pathname = url.pathname;
            let pathProxyIP = null;
            if (pathname.startsWith('/proxyip=')) {
                try {
                    pathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                } catch (e) {
                    // 忽略错误
                }

                if (pathProxyIP && !request.headers.get('Upgrade')) {
                    proxyIP = pathProxyIP;
                    return new Response(`set proxyIP to: ${proxyIP}\n\n`, {
                        headers: { 
                            'Content-Type': 'text/plain; charset=utf-8',
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                        },
                    });
                }
            }

            // 处理API请求
            if (pathname === '/api/add-ssl') {
                return handleApiRequest(request);
            }

            if (request.headers.get('Upgrade') === 'websocket') {
                let wsPathProxyIP = null;
                if (pathname.startsWith('/proxyip=')) {
                    try {
                        wsPathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                    } catch (e) {
                        // 忽略错误
                    }
                }
                
                const customProxyIP = wsPathProxyIP || url.searchParams.get('proxyip') || request.headers.get('proxyip');
                return await handleVlsRequest(request, customProxyIP);
            } else {
                // 返回addssl网页
                return new Response(renderHtml(), {
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }
        } catch (err) {
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};

async function handleVlsRequest(request, customProxyIP) {
    const wsPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wsPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStream(serverSock, earlyData);
    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardUDP(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            const { hasError, message, addressType, port, hostname, rawIndex, version, isUDP } = parseWsPacketHeader(chunk, yourUUID);
            if (hasError) throw new Error(message);

            if (isSpeedTestSite(hostname)) {
                throw new Error('Speedtest site is blocked');
            }
            
            if (isUDP) {
                if (port === 53) isDnsQuery = true;
                else throw new Error('UDP is not supported');
            }
            const respHeader = new Uint8Array([version[0], 0]);
            const rawData = chunk.slice(rawIndex);
            if (isDnsQuery) return forwardUDP(rawData, serverSock, respHeader);
            await forwardTCP(addressType, hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, customProxyIP);
        },
    })).catch((err) => {
    });

    return new Response(null, { status: 101, webSocket: clientSock });
}

async function connect2Socks5(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    let socket;
    try {
        socket = connect({ hostname: host, port: port });
        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();
        
        try {
            const authMethods = username && password ? 
                new Uint8Array([0x05, 0x02, 0x00, 0x02]) :
                new Uint8Array([0x05, 0x01, 0x00]); 
            
            await writer.write(authMethods);
            const methodResponse = await reader.read();
            if (methodResponse.done || methodResponse.value.byteLength < 2) {
                throw new Error('S5 method selection failed');
            }
            
            const selectedMethod = new Uint8Array(methodResponse.value)[1];
            if (selectedMethod === 0x02) {
                if (!username || !password) {
                    throw new Error('S5 requires authentication');
                }
                
                const userBytes = new TextEncoder().encode(username);
                const passBytes = new TextEncoder().encode(password);
                const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
                authPacket[0] = 0x01; 
                authPacket[1] = userBytes.length;
                authPacket.set(userBytes, 2);
                authPacket[2 + userBytes.length] = passBytes.length;
                authPacket.set(passBytes, 3 + userBytes.length);
                await writer.write(authPacket);
                const authResponse = await reader.read();
                if (authResponse.done || new Uint8Array(authResponse.value)[1] !== 0x00) {
                    throw new Error('S5 authentication failed');
                }
            } else if (selectedMethod !== 0x00) {
                throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
            }
            
            const hostBytes = new TextEncoder().encode(targetHost);
            const connectPacket = new Uint8Array(7 + hostBytes.length);
            connectPacket[0] = 0x05;
            connectPacket[1] = 0x01;
            connectPacket[2] = 0x00; 
            connectPacket[3] = 0x03; 
            connectPacket[4] = hostBytes.length;
            connectPacket.set(hostBytes, 5);
            new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
            await writer.write(connectPacket);
            const connectResponse = await reader.read();
            if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) {
                throw new Error('S5 connection failed');
            }
            
            await writer.write(initialData);
            writer.releaseLock();
            reader.releaseLock();
            return socket;
        } catch (error) {
            writer.releaseLock();
            reader.releaseLock();
            throw error;
        }
    } catch (error) {
        if (socket) {
            try {
                socket.close();
            } catch (e) {
                // throw e;
            }
        }
        throw error;
    }
}

async function connect2Http(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    let socket;
    try {
        socket = connect({ hostname: host, port: port });
        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();
        try {
            let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
            connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;
            
            if (username && password) {
                const auth = btoa(`${username}:${password}`);
                connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
            }
            
            connectRequest += `User-Agent: Mozilla/5.0\r\n`;
            connectRequest += `Connection: keep-alive\r\n`;
            connectRequest += '\r\n';
            await writer.write(new TextEncoder().encode(connectRequest));
            let responseBuffer = new Uint8Array(0);
            let headerEndIndex = -1;
            let bytesRead = 0;
            const maxHeaderSize = 8192;
            const startTime = Date.now();
            const timeoutMs = 10000; 
            
            while (headerEndIndex === -1 && bytesRead < maxHeaderSize) {
                if (Date.now() - startTime > timeoutMs) {
                    throw new Error('connection timeout');
                }
                
                const { done, value } = await reader.read();
                if (done) {
                    throw new Error('Connection closed before receiving HTTP response');
                }
                
                const newBuffer = new Uint8Array(responseBuffer.length + value.length);
                newBuffer.set(responseBuffer);
                newBuffer.set(value, responseBuffer.length);
                responseBuffer = newBuffer;
                bytesRead = responseBuffer.length;
                
                for (let i = 0; i < responseBuffer.length - 3; i++) {
                    if (responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a &&
                        responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a) {
                        headerEndIndex = i + 4;
                        break;
                    }
                }
            }
            
            if (headerEndIndex === -1) {
                throw new Error('Invalid HTTP response or response too large');
            }
            
            const headerText = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex));
            const statusLine = headerText.split('\r\n')[0];
            const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
            
            if (!statusMatch) {
                throw new Error(`Invalid response: ${statusLine}`);
            }
            
            const statusCode = parseInt(statusMatch[1]);
            if (statusCode < 200 || statusCode >= 300) {
                throw new Error(`Connection failed with status ${statusCode}: ${statusLine}`);
            }
        
            await writer.write(initialData);
            writer.releaseLock();
            reader.releaseLock();
            
            return socket;
        } catch (error) {
            try { 
                writer.releaseLock(); 
            } catch (e) {}
            try { 
                reader.releaseLock(); 
            } catch (e) {}
            throw error;
        }
    } catch (error) {
        // 确保套接字被正确关闭
        if (socket) {
            try {
                socket.close();
            } catch (e) {
                // 忽略关闭错误
            }
        }
        throw error;
    }
}

async function forwardTCP(addrType, host, portNum, rawData, ws, respHeader, remoteConnWrapper, customProxyIP) {
    async function connectDirect(address, port, data) {
        const remoteSock = connect({ hostname: address, port: port });
        const writer = remoteSock.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return remoteSock;
    }
    
    let proxyConfig = null;
    let shouldUseProxy = false;
    if (customProxyIP) {
        proxyConfig = parseProxyAddress(customProxyIP);
        if (proxyConfig && (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https')) {
            shouldUseProxy = true;
        } else if (!proxyConfig) {
            proxyConfig = parseProxyAddress(proxyIP) || { type: 'direct', host: proxyIP, port: 443 };
        }
    } else {
        proxyConfig = parseProxyAddress(proxyIP) || { type: 'direct', host: proxyIP, port: 443 };
        if (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            shouldUseProxy = true;
        }
    }
    
    async function connectWithProxy() {
        let newSocket;
        if (proxyConfig.type === 'socks5') {
            newSocket = await connect2Socks5(proxyConfig, host, portNum, rawData);
        } else if (proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            newSocket = await connect2Http(proxyConfig, host, portNum, rawData);
        } else {
            newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, rawData);
        }
        
        remoteConnWrapper.socket = newSocket;
        newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
        connectStreams(newSocket, ws, respHeader, null);
    }
    
    if (shouldUseProxy) {
        try {
            await connectWithProxy();
        } catch (err) {
            throw err;
        }
    } else {
        try {
            const initialSocket = await connectDirect(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connectWithProxy);
        } catch (err) {
            await connectWithProxy();
        }
    }
}

function parseWsPacketHeader(chunk, token) {
    if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
    const version = new Uint8Array(chunk.slice(0, 1));
    if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' };
    const optLen = new Uint8Array(chunk.slice(17, 18))[0];
    const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
    let isUDP = false;
    if (cmd === 1) {} else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid cmd' }; }
    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
    let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
    const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
    switch (addressType) {
        case 1: 
            addrLen = 4; 
            hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); 
            break;
        case 2: 
            addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0]; 
            addrValIdx += 1; 
            hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
            break;
        case 3: 
            addrLen = 16; 
            const ipv6 = []; 
            const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
            for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16)); 
            hostname = ipv6.join(':'); 
            break;
        default: 
            return { hasError: true, message: `Invalid address type: ${addressType}` };
    }
    if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
    return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
}

function makeReadableStream(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => { 
                if (!cancelled) controller.enqueue(event.data); 
            });
            socket.addEventListener('close', () => { 
                if (!cancelled) { 
                    closeSocketQuietly(socket); 
                    controller.close(); 
                } 
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error); 
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() { 
            cancelled = true; 
            closeSocketQuietly(socket); 
        }
    });
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasData = true;
                if (webSocket.readyState !== WebSocket.OPEN) controller.error('ws.readyState is not open');
                if (header) { 
                    const response = new Uint8Array(header.length + chunk.byteLength);
                    response.set(header, 0);
                    response.set(chunk, header.length);
                    webSocket.send(response.buffer); 
                    header = null; 
                } else { 
                    webSocket.send(chunk); 
                }
            },
            abort() {},
        })
    ).catch((err) => { 
        console.error('Stream pipe error:', err);
        closeSocketQuietly(webSocket); 
    });
    if (!hasData && retryFunc) {
        console.log('No data received, retrying...');
        await retryFunc();
    }
}

async function forwardUDP(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessHeader) { 
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null; 
                    } else { 
                        webSocket.send(chunk); 
                    }
                }
            },
        }));
    } catch (error) {
        // console.error('UDP forward error:', error);
    }
}
