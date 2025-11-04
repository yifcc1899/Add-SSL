addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  if (pathname === '/api/add-ssl') {
    return handleApiRequest(request);
  }

  return new Response(renderHtml(), {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

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
