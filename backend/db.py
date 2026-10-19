from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    """用户表：账号密码登录，密码用 werkzeug 哈希存储"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.now)
    # 用户级 AI 配置（可选，留空则用环境变量全局配置）
    ai_key = db.Column(db.String(255), default="")
    ai_base_url = db.Column(db.String(255), default="")
    ai_model = db.Column(db.String(100), default="")


class Asset(db.Model):
    """资产表：被扫描的目标 IP / 域名"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)  # e.g. http://127.0.0.1:8080
    name = db.Column(db.String(100))
    create_time = db.Column(db.DateTime, default=datetime.now)


class ScanTask(db.Model):
    """扫描任务表：异步执行，记录进度与原始结果"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    status = db.Column(db.String(20), default="pending")   # pending/running/finish/failed
    progress = db.Column(db.Integer, default=0)
    port_result = db.Column(db.Text)
    vul_result = db.Column(db.Text)
    create_time = db.Column(db.DateTime, default=datetime.now)


class Vulnerability(db.Model):
    """漏洞表：从扫描结果中拆分出来，按任务归档"""
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('scan_task.id'), nullable=False)
    vul_name = db.Column(db.String(200))
    level = db.Column(db.String(20))   # high / medium / low
    desc = db.Column(db.Text)
