# 🌐 Add-SSL: 自动为 Cloudflare 域名添加 SSL 证书&集成老王sni

一个基于 Cloudflare Workers 的轻量级 Web 工具，支持为任意接入 Cloudflare 的域名快速启用 Universal SSL 证书。支持自定义域名、证书颁发机构选择、自动续期，适合自建服务、内网穿透、IPv6 域名等场景。

根据老王的cf项目核心，定制了一个sni部署的版本，代码是_worker.js这个。部署完成网页是addssl，需手动配置节点参数
节点path为SSpath变量或uuid开头，示例：/5dc15e15-f285-4a9d-959b-0e4fbdd77b63/?ed=2560 带proxyip的示例：/5dc15e15-f285-4a9d-959b-0e4fbdd77b63/?ed=2560&proxyip=xxxx 小火箭可去掉?ed=2560& 来自定义proxyip或全局出站

觉得有用点个收藏&Fork

<img width="508" height="630" alt="image" src="https://github.com/user-attachments/assets/faf88a99-f498-4a36-bc91-8ea5e7786c45" />


## ✨ 功能特性

- ✅ 支持自定义域名添加 SSL 证书
- ✅ 可选证书颁发机构（SSL.com / Let's Encrypt / Google / Sectigo）
- ✅ 自动续期，无需手动干预
- ✅ 响应式 UI，适配手机端
- ✅ 一键部署，无需服务器

## 🚀 使用方法

1. 部署本项目到 Cloudflare Workers
2. 访问你的 Worker 地址（如 `https://ssl.example.workers.dev`）
3. 填写 Cloudflare 邮箱、Zone ID、API Key、自定义域名
4. 点击「添加 SSL 证书」按钮，等待提示 ✅

## 📦 部署方式

### 使用 Wrangler 部署

```bash
git clone https://github.com/yifcc1899/Add-SSL.git
cd Add-SSL
wrangler publish

