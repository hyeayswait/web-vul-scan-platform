"""
扫描核心：端口探测 + 简易 Web 漏洞检测。

⚠️ 安全声明：本模块仅允许对用户自己授权的靶机（DVWA / WebGoat / 本地 127.0.0.1）进行扫描。
未经授权扫描公网资产属于违法行为。
"""
import json
import socket
from urllib.parse import urlparse

import requests

# 只允许扫这些常用端口，降低风险与噪音
ALLOWED_PORTS = [21, 22, 80, 443, 3306, 6379, 8000, 8080, 8443]

# 优先尝试 nmap；不可用时降级为 socket 探测（保证项目开箱可跑）
try:
    import nmap  # type: ignore
    _HAS_NMAP = True
except Exception:
    _HAS_NMAP = False


def _extract_host(target: str) -> str:
    """从 http://127.0.0.1:8080 中提取 host 部分"""
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split(":")[0]


def scan_port(target: str) -> str:
    """对目标做端口探测，返回 JSON 字符串"""
    host = _extract_host(target)
    result = {}

    if _HAS_NMAP:
        try:
            nm = nmap.PortScanner()
            nm.scan(host, ",".join(str(p) for p in ALLOWED_PORTS), timeout=5)
            for h in nm.all_hosts():
                result[h] = {}
                for proto in nm[h].all_protocols():
                    for port in nm[h][proto].keys():
                        result[h][str(port)] = nm[h][proto][port]["state"]
            return json.dumps(result, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"nmap 执行失败: {e}"}, ensure_ascii=False)

    # 降级：socket connect 探测
    open_ports = {}
    for port in ALLOWED_PORTS:
        try:
            with socket.create_connection((host, port), timeout=1):
                open_ports[str(port)] = "open"
        except Exception:
            continue
    result[host] = open_ports
    return json.dumps(result, ensure_ascii=False)


def scan_vul(target: str) -> str:
    """
    简易漏洞检测（教学用）：
    - XSS：把 <script>alert(1)</script> 拼到常见参数里，看是否原样回显
    - SQL 注入：id=1' or 1=1-- 看是否出现数据库报错特征
    """
    vul_list = []
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    # 常见探测参数
    probes = [
        {
            "name": "反射型 XSS 检测",
            "url": target.rstrip("/") + "/?q=<script>alert(1)</script>",
            "match": "<script>alert(1)</script>",
            "level": "medium",
            "desc": "请求参数中的脚本被原样回显到页面，存在反射型 XSS 风险。",
        },
        {
            "name": "SQL 注入报错检测",
            "url": target.rstrip("/") + "/?id=1' or 1=1--",
            "match": None,  # 用关键字集合判断
            "keywords": ["MySQL", "SQL syntax", "ORA-", "PostgreSQL", "sqlite3.OperationalError"],
            "level": "high",
            "desc": "注入点触发数据库报错信息，可能存在 SQL 注入漏洞。",
        },
    ]

    for p in probes:
        try:
            r = requests.get(p["url"], timeout=3, verify=False)
            text = r.text or ""
            if p["match"] and p["match"] in text:
                vul_list.append({
                    "vul_name": p["name"],
                    "level": p["level"],
                    "desc": p["desc"],
                })
            elif p.get("keywords") and any(k in text for k in p["keywords"]):
                vul_list.append({
                    "vul_name": p["name"],
                    "level": p["level"],
                    "desc": p["desc"],
                })
        except Exception:
            continue

    return json.dumps(vul_list, ensure_ascii=False)
