# Web Asset Probing & Vulnerability Inspection Platform

[![Vue3](https://img.shields.io/badge/frontend-Vue%203-42b883)](https://vuejs.org/)
[![Flask](https://img.shields.io/badge/backend-Flask-000000)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/db-SQLite-0f80c1)](https://www.sqlite.org/)
[![Docker](https://img.shields.io/badge/deploy-Docker%20Compose-2496ed)](https://docs.docker.com/compose/)
[![License](https://img.shields.io/badge/license-MIT-blue)](#license)

> A full-stack, education-focused web asset probing & vulnerability inspection demo.
> Built with **Vue 3 + Element Plus + Flask + SQLAlchemy + SQLite + ECharts**, with an optional **AI assistant** that explains findings and suggests remediation steps.

> ⚠️ **For authorized lab use only.** This tool is designed for students and CTF/skill-contest demos against local targets such as DVWA, WebGoat, or `127.0.0.1`. **Never scan hosts you do not own or have explicit written permission to test.** Unauthorized scanning may violate the Computer Fraud and Abuse Act, the PRC Cybersecurity Law, and other local regulations. The author assumes no liability for misuse.

## Features

- 🔐 User registration / login with **JWT** (passwords hashed via Werkzeug)
- 🗂️ Asset inventory (IP / domain / URL)
- ⚡ Async scan tasks with real-time progress polling
- 🌐 Port probing (nmap when available, falls back to raw socket probing)
- 🐛 Basic web vuln detection: reflected XSS & SQLi error-based signatures
- 📊 ECharts dashboard: vuln severity pie chart, task progress
- 📄 Export a Chinese/English-friendly **PDF inspection report**
- 🤖 **AI assistant** (OpenAI-compatible: DeepSeek / Qwen / GLM / Ollama) — explains findings, suggests remediation, suggests next learning steps. Gracefully falls back to local rules when no API key is configured.
- 🐳 One-command startup via `docker compose up -d --build`

## Quick Start

```bash
# Backend
cd backend
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000

# Frontend (new terminal)
cd frontend
npm install
npm run dev              # http://127.0.0.1:5173

# Or one-shot with Docker:
docker compose up -d --build   # frontend http://127.0.0.1:8080
```

## Tech Stack

| Layer | Tech |
| --- | --- |
| Frontend | Vue 3 + Vite + Element Plus + ECharts + Axios |
| Backend | Python Flask + Flask-JWT-Extended + SQLAlchemy |
| Database | SQLite (zero-config) |
| Scanner | python-nmap (optional) + requests |
| Report | reportlab (built-in CID Chinese font) |
| AI | OpenAI-compatible Chat Completions API |

---

# Web 资产探测与漏洞巡检平台

> 前后端分离的 Web 资产探测与漏洞巡检演示平台，用于**网络安全教学 / 课程作业 / 技能竞赛**。

---

## ⚠️ 重要安全声明（务必先读）

本项目仅作为**安全教学与自测工具**，**只允许对自己拥有或已获书面授权的目标**（例如本地搭建的 DVWA、WebGoat、`127.0.0.1` 靶机）进行扫描。

- **禁止**未经授权扫描任何公网网站、服务器、IoT 设备；
- 未经授权的扫描、探测、漏洞利用行为，可能违反《中华人民共和国网络安全法》《刑法》第 285/286 条等法律法规；
- 因滥用本工具造成的一切法律责任，由使用者自行承担，与作者无关。

---

## 项目简介

一个简化版的"资产-任务-漏洞"巡检平台：

1. 用户注册 / 登录（JWT 鉴权）
2. 录入待巡检资产（IP / 域名 / URL）
3. 一键启动异步扫描任务：
   - 常用端口探测（优先 nmap，无 nmap 时降级为 socket 探测）
   - 简易 Web 漏洞特征检测（反射型 XSS、SQL 报错注入）
4. 实时查看扫描进度（前端 3s 轮询）
5. 查看漏洞列表 + ECharts 漏洞等级饼图
6. 一键导出 PDF 漏洞巡检报告

## 技术栈

| 端 | 技术 |
| --- | --- |
| 前端 | Vue 3 + Vite + Element Plus + ECharts + Axios |
| 后端 | Python Flask + SQLAlchemy + Flask-JWT-Extended |
| 数据库 | SQLite（零配置，开箱即用） |
| 扫描 | python-nmap（可选）+ requests |
| 报告 | reportlab（PDF，内置中文字体） |

## 目录结构

```
web-vul-scan-platform/
├── backend/
│   ├── app.py            # Flask 入口与全部路由
│   ├── db.py            # SQLAlchemy 模型
│   ├── scanner.py       # 端口探测 + 漏洞检测
│   ├── report.py         # PDF 报告生成
│   ├── requirements.txt
│   └── reports/         # 生成的 PDF 报告（运行后产生）
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.js
│       └── App.vue
├── docs/
│   └── API.md            # 接口文档
├── .gitignore
└── README.md
```

## 快速启动

### 1. 后端

```bash
cd backend
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
python app.py
# 后端跑在 http://127.0.0.1:5000
```

> 可选：安装 nmap 以启用更准确的端口扫描（不装也能跑，会自动降级为 socket 探测）。
> - Windows：到 https://nmap.org/download.html 下载安装包
> - Ubuntu/Debian：`sudo apt install nmap`
> - macOS：`brew install nmap`

### 2. 前端

```bash
cd frontend
npm install
npm run dev
# 前端跑在 http://127.0.0.1:5173
```

浏览器打开 http://127.0.0.1:5173 ，先注册账号，登录后即可使用。

### 3. Docker Compose 一键启动（推荐）

已经装好 Docker / Docker Compose 的话，一条命令起全部：

```bash
docker compose up -d --build
```

- 前端访问：http://127.0.0.1:8080
- 后端 API：http://127.0.0.1:5000
- SQLite 数据库与生成的 PDF 报告会挂载到本地 `backend/vul.db` 和 `backend/reports/`

### 4. 推荐靶机

- [DVWA](https://github.com/digininja/DVWA)
- [WebGoat](https://github.com/WebGoat/WebGoat)
- 本地搭一个带参数的小站点作为练习目标

## 已实现功能

- [x] 用户注册 / 登录（密码 werkzeug 哈希存储，JWT 鉴权）
- [x] 资产录入 / 删除
- [x] 异步扫描任务（后台线程执行，不阻塞前端）
- [x] 实时进度展示（前端轮询）
- [x] 端口探测（nmap 优先，socket 降级）
- [x] 简易 XSS / SQL 注入特征检测
- [x] 漏洞列表 + 等级统计饼图
- [x] PDF 报告导出（中文，自动生成）
- [x] **AI 辅助安全分析**（漏洞解读、修复建议、下一步巡检引导，兼容 OpenAI / DeepSeek / 通义 / 智谱 / Ollama）

## AI 功能配置（可选）

不配置也能用，会自动降级为本地规则模板。两种配置方式：

### 方式一：网页内设置（推荐）

登录后，点击右上角「🤖 AI 设置」，填入：

- **API Key**：你的大模型 Key
- **Base URL**：接口地址
- **模型名**：例如 `deepseek-chat`

保存后即时生效，Key 不会在网页回显完整内容。

### 方式二：环境变量（全局兜底）

启动后端前设置：

```bash
# 以 DeepSeek 为例
export OPENAI_API_KEY="sk-xxxxxxxx"
export OPENAI_BASE_URL="https://api.deepseek.com/v1"
export OPENAI_MODEL="deepseek-chat"

# 或本地 Ollama
# export OPENAI_BASE_URL="http://127.0.0.1:11434/v1"
# export OPENAI_MODEL="qwen2.5"

python app.py
```

配置优先级：**网页内用户配置 > 环境变量 > 本地规则模板**。

兼容任何 OpenAI 接口（DeepSeek / 通义 / 智谱 / Kimi / 本地 Ollama）。

> ⚠️ AI 模块只做"扫描结果解读 + 修复建议 + 教学引导"，不生成攻击性 exploit、不做自动利用。

## 后续可扩展

- 任务队列换成 Celery + Redis
- 扫描结果持久化更多字段（服务指纹、响应头）
- 增加更多 POC：目录遍历、文件包含、未授权访问
- 定时扫描、邮件告警
- 前端增加路由与多页面（Vue Router）

## License

仅用于学习交流，请勿用于非法用途。
