"""
AI 辅助安全分析模块（教学向）。

⚠️ 边界：本模块只做"扫描结果解读 + 修复建议 + 下一步教学引导"，
    不生成攻击性 exploit、不做自动利用、不提供任何可直接用于入侵的 payload。

配置优先级：用户在网页设置里填的 Key > 环境变量全局 Key > 本地规则降级。

环境变量（全局兜底）：
  OPENAI_API_KEY
  OPENAI_BASE_URL   例如 https://api.deepseek.com/v1 或 http://127.0.0.1:11434/v1
  OPENAI_MODEL      例如 deepseek-chat / qwen-plus / gpt-3.5-turbo
"""
import os
import json
import requests

# 全局兜底配置（来自环境变量）
ENV_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
ENV_BASE = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/")
ENV_MODEL = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo").strip()

SYSTEM_PROMPT = (
    "你是一位网络安全教学助教，只对学生已经授权的本地靶机做安全分析。"
    "你的任务：用中文解释扫描结果的风险含义、给出修复建议、"
    "并指导学生下一步在合法的实验环境中学习什么。"
    "严禁生成攻击性 exploit、严禁提供可直接入侵他人系统的步骤、"
    "严禁鼓励未授权测试。"
)


def resolve_config(user_cfg: dict) -> dict:
    """合并用户配置与环境变量，返回最终生效的 config"""
    return {
        "key": (user_cfg.get("ai_key") or "").strip() or ENV_KEY,
        "base_url": (user_cfg.get("ai_base_url") or "").strip().rstrip("/") or ENV_BASE,
        "model": (user_cfg.get("ai_model") or "").strip() or ENV_MODEL,
    }


def is_available(cfg: dict) -> bool:
    return bool(cfg.get("key"))


def _chat(cfg: dict, user_prompt: str, timeout: int = 30) -> str:
    """调用 OpenAI 兼容接口；失败时抛出异常，由上层降级。"""
    resp = requests.post(
        f"{cfg['base_url']}/chat/completions",
        headers={
            "Authorization": f"Bearer {cfg['key']}",
            "Content-Type": "application/json",
        },
        json={
            "model": cfg["model"],
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


# ---------- 本地规则模板（无 Key 时降级用） ----------
def _local_explain(vuls: list) -> str:
    if not vuls:
        return "本次扫描未发现已知特征的漏洞。建议持续关注端口暴露面，并保持依赖组件更新。"
    lines = ["【本地规则解读】本次共发现 %d 个疑似漏洞：" % len(vuls)]
    fix_map = {
        "反射型 XSS 检测": "修复建议：对所有用户输入做输出编码（HTML encode），"
                          "设置 Content-Security-Policy 响应头，过滤 <script> 等标签。",
        "SQL 注入报错检测": "修复建议：使用参数化查询 / ORM，禁止拼接 SQL；"
                           "关闭数据库报错回显，最小化数据库账号权限。",
    }
    for v in vuls:
        lines.append(f"- [{v['level']}] {v['vul_name']}：{v['desc']}")
        lines.append(f"  → {fix_map.get(v['vul_name'], '建议升级组件并做代码审计。')}")
    return "\n".join(lines)


def _local_suggest(target: str, port_result: str) -> str:
    tips = [f"【本地规则】针对 {target} 的下一步学习建议："]
    try:
        ports = json.loads(port_result)
        open_ports = []
        for host, pmap in ports.items():
            open_ports.extend(int(p) for p, s in pmap.items() if s == "open")
    except Exception:
        open_ports = []

    port_tips = {
        21: "FTP：检查是否允许匿名登录，是否使用明文协议，建议改用 SFTP。",
        22: "SSH：检查是否禁用密码登录、改用密钥，是否限制登录 IP。",
        80: "HTTP：检查目录遍历、默认后台、中间件版本是否有已知 CVE。",
        443: "HTTPS：检查证书有效期、TLS 版本是否过旧（禁用 SSLv3/TLS1.0）。",
        3306: "MySQL：检查是否对公网暴露、是否使用弱口令、是否限制来源 IP。",
        6379: "Redis：检查是否未授权访问、是否绑定 0.0.0.0，这是常见入侵入口。",
        8080: "常见 Web 后台：检查管理路径是否可被爆破，是否有默认口令。",
    }
    for p in sorted(open_ports):
        if p in port_tips:
            tips.append(f"- 端口 {p} 开放：{port_tips[p]}")
    if len(tips) == 1:
        tips.append("- 未发现明显开放端口，建议核对目标地址与网络可达性。")
    tips.append("提示：以上检查请仅在你自己的靶机上进行，禁止扫描未授权资产。")
    return "\n".join(tips)


# ---------- 对外接口函数 ----------
def explain_vulns(target: str, vuls: list, cfg: dict) -> dict:
    """解读漏洞列表，返回 {engine, text}"""
    if not is_available(cfg):
        return {"engine": "local-rules", "text": _local_explain(vuls)}
    try:
        prompt = (
            f"扫描目标：{target}\n"
            f"漏洞列表：{json.dumps(vuls, ensure_ascii=False)}\n\n"
            "请用中文分点输出：\n"
            "1) 整体风险评级（高/中/低）与理由；\n"
            "2) 每个漏洞的危害说明；\n"
            "3) 每个漏洞的具体修复建议；\n"
            "4) 在 DVWA / WebGoat 这类教学靶场上，学生可以怎么复现学习（仅教学）。"
        )
        return {"engine": f"llm:{cfg['model']}", "text": _chat(cfg, prompt)}
    except Exception as e:
        return {"engine": "local-rules(fallback)",
                "text": f"AI 调用失败（{e}），已降级为本地规则：\n" + _local_explain(vuls)}


def suggest_next(target: str, port_result: str, vuls: list, cfg: dict) -> dict:
    """给出下一步巡检/学习建议"""
    if not is_available(cfg):
        return {"engine": "local-rules", "text": _local_suggest(target, port_result)}
    try:
        prompt = (
            f"扫描目标：{target}\n"
            f"端口探测结果：{port_result}\n"
            f"已发现漏洞：{json.dumps(vuls, ensure_ascii=False)}\n\n"
            "请用中文给出 3-5 条下一步教学建议，"
            "告诉学生在合法靶场环境下应该重点检查哪些点、学习哪些知识点。"
        )
        return {"engine": f"llm:{cfg['model']}", "text": _chat(cfg, prompt)}
    except Exception as e:
        return {"engine": "local-rules(fallback)",
                "text": f"AI 调用失败（{e}），已降级：\n" + _local_suggest(target, port_result)}


def summarize_report(target: str, vuls: list, cfg: dict) -> str:
    """给 PDF 报告末尾生成一段自然语言结论"""
    if not is_available(cfg):
        return _local_explain(vuls)
    try:
        prompt = (
            f"目标：{target}\n漏洞：{json.dumps(vuls, ensure_ascii=False)}\n"
            "请用 150 字以内中文写一段巡检结论与修复优先级建议。"
        )
        return _chat(cfg, prompt)
    except Exception:
        return _local_explain(vuls)
