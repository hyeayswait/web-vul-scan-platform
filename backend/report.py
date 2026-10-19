"""
生成 PDF 漏洞巡检报告。使用 reportlab 内置 CID 中文字体，无需额外字体文件。
"""
import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

import ai_helper

REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

# 注册中文 CID 字体（reportlab 自带，跨平台可用）
pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))


def generate_report(task, asset, vuls, ai_cfg=None) -> str:
    """
    task: ScanTask 对象
    asset: Asset 对象
    vuls: list[Vulnerability]
    ai_cfg: dict（ai_helper 解析后的配置），可选
    返回生成的 PDF 文件绝对路径
    """
    filename = f"report_task_{task.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    path = os.path.join(REPORT_DIR, filename)

    doc = SimpleDocTemplate(path, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("title", parent=styles["Title"],
                                 fontName="STSong-Light", fontSize=20, leading=26)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"],
                        fontName="STSong-Light", fontSize=14, leading=20)
    body = ParagraphStyle("body", parent=styles["Normal"],
                         fontName="STSong-Light", fontSize=10.5, leading=16)

    story = []
    story.append(Paragraph("Web 资产探测与漏洞巡检报告", title_style))
    story.append(Spacer(1, 0.5*cm))

    # 基本信息
    info = [
        ["任务编号", str(task.id)],
        ["扫描目标", asset.target],
        ["资产名称", asset.name or "-"],
        ["任务状态", task.status],
        ["扫描时间", task.create_time.strftime("%Y-%m-%d %H:%M:%S")],
        ["报告生成时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
    ]
    t = Table(info, colWidths=[4*cm, 11*cm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "STSong-Light"),
        ("FONTSIZE", (0, 0), (-1, -1), 10.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.6*cm))

    # 漏洞统计
    high = sum(1 for v in vuls if v.level == "high")
    mid = sum(1 for v in vuls if v.level == "medium")
    low = sum(1 for v in vuls if v.level == "low")
    story.append(Paragraph("一、漏洞统计", h2))
    stat = [
        ["高危", "中危", "低危", "合计"],
        [str(high), str(mid), str(low), str(len(vuls))],
    ]
    st = Table(stat, colWidths=[3.75*cm]*4)
    st.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "STSong-Light"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(st)
    story.append(Spacer(1, 0.6*cm))

    # 漏洞明细
    story.append(Paragraph("二、漏洞明细", h2))
    if not vuls:
        story.append(Paragraph("本次扫描未发现已知特征的漏洞。", body))
    else:
        rows = [["编号", "漏洞名称", "等级", "描述"]]
        for i, v in enumerate(vuls, 1):
            rows.append([str(i), v.vul_name, v.level,
                         Paragraph(v.desc, body)])
        vt = Table(rows, colWidths=[1.2*cm, 4*cm, 1.8*cm, 8*cm])
        vt.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), "STSong-Light"),
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(vt)

    story.append(Spacer(1, 0.8*cm))

    # AI 巡检结论（无 Key 时自动降级为本地规则模板）
    story.append(Paragraph("三、AI 巡检结论", h2))
    vuls_data = [{"vul_name": v.vul_name, "level": v.level, "desc": v.desc} for v in vuls]
    cfg = ai_cfg or ai_helper.resolve_config({})
    ai_text = ai_helper.summarize_report(asset.target, vuls_data, cfg)
    engine = "大模型" if ai_helper.is_available(cfg) else "本地规则引擎"
    story.append(Paragraph(f"（由 {engine} 生成，仅供教学参考）", body))
    story.append(Spacer(1, 0.2*cm))
    # 按行拆段，避免长文本溢出
    for line in ai_text.split("\n"):
        line = line.strip()
        if line:
            story.append(Paragraph(line, body))
    story.append(Spacer(1, 0.6*cm))

    story.append(Paragraph(
        "免责声明：本报告仅用于授权范围内的安全教学与自测。未经授权扫描第三方资产属于违法行为。",
        body))

    doc.build(story)
    return path
