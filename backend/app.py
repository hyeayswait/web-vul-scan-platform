"""
Web 资产探测与漏洞巡检平台 - 后端入口
技术栈：Flask + SQLAlchemy + SQLite + Flask-JWT-Extended

⚠️ 仅允许对自己授权的靶机（DVWA / WebGoat / 127.0.0.1）进行扫描。
"""
import json
import threading

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash

from db import db, User, Asset, ScanTask, Vulnerability
from scanner import scan_port, scan_vul
from report import generate_report
import ai_helper

app = Flask(__name__)
CORS(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///vul.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "change-me-in-production-9f8a7b6c5d"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 86400  # 1 天

db.init_app(app)
jwt = JWTManager(app)

with app.app_context():
    db.create_all()


# ---------- 认证 ----------
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"msg": "用户名或密码不能为空"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "用户名已存在"}), 400
    u = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(u)
    db.session.commit()
    return jsonify({"msg": "注册成功"})


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    u = User.query.filter_by(username=username).first()
    if not u or not check_password_hash(u.password_hash, password):
        return jsonify({"msg": "用户名或密码错误"}), 401
    token = create_access_token(identity=str(u.id))
    return jsonify({"token": token, "username": username})


# ---------- 资产管理 ----------
@app.route("/api/asset/list", methods=["GET"])
@jwt_required()
def asset_list():
    uid = int(get_jwt_identity())
    assets = Asset.query.filter_by(user_id=uid).order_by(Asset.id.desc()).all()
    return jsonify([
        {"id": a.id, "target": a.target, "name": a.name} for a in assets
    ])


@app.route("/api/asset/add", methods=["POST"])
@jwt_required()
def asset_add():
    uid = int(get_jwt_identity())
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    name = data.get("name", "").strip()
    if not target:
        return jsonify({"msg": "目标地址不能为空"}), 400
    a = Asset(user_id=uid, target=target, name=name)
    db.session.add(a)
    db.session.commit()
    return jsonify({"msg": "添加成功", "id": a.id})


@app.route("/api/asset/del/<int:aid>", methods=["DELETE"])
@jwt_required()
def asset_del(aid):
    uid = int(get_jwt_identity())
    a = Asset.query.filter_by(id=aid, user_id=uid).first()
    if not a:
        return jsonify({"msg": "资产不存在"}), 404
    db.session.delete(a)
    db.session.commit()
    return jsonify({"msg": "删除成功"})


# ---------- 扫描任务 ----------
def _run_scan(task_id: int, target: str):
    """后台线程：执行端口探测 + 漏洞检测，写回任务状态"""
    with app.app_context():
        task = ScanTask.query.get(task_id)
        task.status = "running"
        task.progress = 20
        db.session.commit()

        port_data = scan_port(target)
        task.port_result = port_data
        task.progress = 60
        db.session.commit()

        vul_data = scan_vul(target)
        task.vul_result = vul_data
        task.progress = 90
        db.session.commit()

        # 解析漏洞入库
        try:
            vuls = json.loads(vul_data)
            for v in vuls:
                db.session.add(Vulnerability(
                    task_id=task_id,
                    vul_name=v["vul_name"],
                    level=v["level"],
                    desc=v["desc"],
                ))
        except Exception:
            pass

        task.progress = 100
        task.status = "finish"
        db.session.commit()


@app.route("/api/task/start", methods=["POST"])
@jwt_required()
def task_start():
    uid = int(get_jwt_identity())
    data = request.get_json() or {}
    aid = data.get("asset_id")
    asset = Asset.query.filter_by(id=aid, user_id=uid).first()
    if not asset:
        return jsonify({"msg": "资产不存在"}), 404

    task = ScanTask(user_id=uid, asset_id=asset.id, status="pending", progress=0)
    db.session.add(task)
    db.session.commit()

    t = threading.Thread(target=_run_scan, args=(task.id, asset.target), daemon=True)
    t.start()
    return jsonify({"task_id": task.id, "msg": "扫描任务已启动"})


@app.route("/api/task/list", methods=["GET"])
@jwt_required()
def task_list():
    uid = int(get_jwt_identity())
    tasks = ScanTask.query.filter_by(user_id=uid).order_by(ScanTask.id.desc()).all()
    out = []
    for t in tasks:
        asset = Asset.query.get(t.asset_id)
        out.append({
            "id": t.id,
            "asset_target": asset.target if asset else "-",
            "asset_name": asset.name if asset else "-",
            "status": t.status,
            "progress": t.progress,
            "create_time": t.create_time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return jsonify(out)


# ---------- 漏洞 & 报告 ----------
@app.route("/api/vul/list/<int:task_id>", methods=["GET"])
@jwt_required()
def vul_list(task_id):
    uid = int(get_jwt_identity())
    task = ScanTask.query.filter_by(id=task_id, user_id=uid).first()
    if not task:
        return jsonify({"msg": "任务不存在"}), 404
    vuls = Vulnerability.query.filter_by(task_id=task_id).all()
    return jsonify([
        {"id": v.id, "vul_name": v.vul_name, "level": v.level, "desc": v.desc}
        for v in vuls
    ])


@app.route("/api/report/export/<int:task_id>", methods=["GET"])
@jwt_required()
def report_export(task_id):
    uid = int(get_jwt_identity())
    task = ScanTask.query.filter_by(id=task_id, user_id=uid).first()
    if not task:
        return jsonify({"msg": "任务不存在"}), 404
    asset = Asset.query.get(task.asset_id)
    vuls = Vulnerability.query.filter_by(task_id=task_id).all()
    user = User.query.get(uid)
    cfg = ai_helper.resolve_config({
        "ai_key": user.ai_key, "ai_base_url": user.ai_base_url, "ai_model": user.ai_model
    })
    path = generate_report(task, asset, vuls, cfg)
    return send_file(path, as_attachment=True,
                     download_name=f"vul_report_task_{task_id}.pdf")


# ---------- AI 辅助分析（教学向，不做攻击） ----------
def _current_cfg():
    uid = int(get_jwt_identity())
    u = User.query.get(uid)
    return ai_helper.resolve_config({
        "ai_key": u.ai_key, "ai_base_url": u.ai_base_url, "ai_model": u.ai_model
    })


@app.route("/api/ai/config", methods=["GET"])
@jwt_required()
def ai_config_get():
    """返回当前用户的 AI 配置（Key 做掩码，避免回显完整密钥）"""
    uid = int(get_jwt_identity())
    u = User.query.get(uid)
    key = u.ai_key or ""
    masked = (key[:4] + "****" + key[-4:]) if len(key) > 8 else ("****" if key else "")
    return jsonify({
        "ai_key": masked,
        "ai_base_url": u.ai_base_url or "",
        "ai_model": u.ai_model or "",
        "has_key": bool(key),
    })


@app.route("/api/ai/config", methods=["POST"])
@jwt_required()
def ai_config_set():
    """保存用户 AI 配置；ai_key 传空串则清空，传 'KEEP' 则不修改"""
    uid = int(get_jwt_identity())
    u = User.query.get(uid)
    data = request.get_json() or {}
    u.ai_base_url = (data.get("ai_base_url") or "").strip()
    u.ai_model = (data.get("ai_model") or "").strip()
    key = (data.get("ai_key") or "").strip()
    if key and key != "KEEP":
        u.ai_key = key
    elif key == "":
        u.ai_key = ""
    db.session.commit()
    return jsonify({"msg": "AI 配置已保存"})


@app.route("/api/ai/status", methods=["GET"])
@jwt_required()
def ai_status():
    cfg = _current_cfg()
    return jsonify({
        "enabled": ai_helper.is_available(cfg),
        "engine": cfg["model"] if ai_helper.is_available(cfg) else "local-rules",
    })


@app.route("/api/ai/explain/<int:task_id>", methods=["POST"])
@jwt_required()
def ai_explain(task_id):
    uid = int(get_jwt_identity())
    task = ScanTask.query.filter_by(id=task_id, user_id=uid).first()
    if not task:
        return jsonify({"msg": "任务不存在"}), 404
    asset = Asset.query.get(task.asset_id)
    vuls = Vulnerability.query.filter_by(task_id=task_id).all()
    vuls_data = [{"vul_name": v.vul_name, "level": v.level, "desc": v.desc} for v in vuls]
    result = ai_helper.explain_vulns(asset.target, vuls_data, _current_cfg())
    return jsonify(result)


@app.route("/api/ai/suggest/<int:task_id>", methods=["POST"])
@jwt_required()
def ai_suggest(task_id):
    uid = int(get_jwt_identity())
    task = ScanTask.query.filter_by(id=task_id, user_id=uid).first()
    if not task:
        return jsonify({"msg": "任务不存在"}), 404
    asset = Asset.query.get(task.asset_id)
    vuls = Vulnerability.query.filter_by(task_id=task_id).all()
    vuls_data = [{"vul_name": v.vul_name, "level": v.level, "desc": v.desc} for v in vuls]
    result = ai_helper.suggest_next(asset.target, task.port_result or "{}", vuls_data, _current_cfg())
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
