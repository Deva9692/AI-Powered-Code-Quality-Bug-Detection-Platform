from pathlib import Path

FILES_CONTENT = {
    "app/modules/report_management/pdf_exporter.py": '''import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from app.database.models import Analysis

def generate_analysis_pdf(analysis: Analysis, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    filename = f"audit_report_{analysis.id}.pdf"
    filepath = os.path.join(output_dir, filename)

    doc = SimpleDocTemplate(filepath, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle("ReportTitle", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#0f172a"), spaceAfter=10)
    sub_style = ParagraphStyle("SubTitle", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#475569"), spaceAfter=18)
    code_style = ParagraphStyle("CodeBlock", parent=styles["Code"], fontSize=8, backColor=colors.HexColor("#f1f5f9"), borderPadding=6, spaceAfter=8)

    elements.append(Paragraph(f"AI Code Quality & Security Audit Report — #{analysis.id}", title_style))
    elements.append(Paragraph(f"File: {analysis.filename} | Language: {analysis.language.upper()} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", sub_style))

    summary_data = [
        ["Metric", "Value", "Metric", "Value"],
        ["Quality Score", f"{analysis.quality_score:.1f} / 100", "Security Score", f"{analysis.security_score:.1f} / 100"],
        ["Maintainability Index", f"{analysis.maintainability_index:.1f}", "Cyclomatic Complexity", f"{analysis.cyclomatic_complexity:.2f}"],
        ["Lines of Code (LOC)", str(analysis.loc), "ML Defect Risk", f"{analysis.ml_bug_probability * 100:.1f}%"],
    ]

    t = Table(summary_data, colWidths=[130, 120, 130, 120])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph(f"Detected Vulnerabilities & Code Issues ({len(analysis.bugs)})", styles["Heading2"]))
    elements.append(Spacer(1, 8))

    if not analysis.bugs:
        elements.append(Paragraph("No security vulnerabilities or static bugs detected. Code passed all quality gates.", styles["Normal"]))
    else:
        for idx, bug in enumerate(analysis.bugs, 1):
            header = f"{idx}. [{bug.severity.upper()}] {bug.cwe_id or 'ISSUE'} — {bug.title} (Line {bug.line_number})"
            elements.append(Paragraph(header, styles["Heading3"]))
            elements.append(Paragraph(f"<b>Description:</b> {bug.description}", styles["Normal"]))
            elements.append(Paragraph(f"<b>Recommendation:</b> {bug.recommendation}", styles["Normal"]))
            if bug.patch_diff:
                elements.append(Spacer(1, 4))
                elements.append(Paragraph("<b>Synthesized Git Patch:</b>", styles["Normal"]))
                safe_patch = bug.patch_diff.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\\n", "<br/>")
                elements.append(Paragraph(safe_patch, code_style))
            elements.append(Spacer(1, 10))

    doc.build(elements)
    return filepath
''',

    "app/api/routes/analysis_routes.py": '''import os
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, send_file, current_app
from app.services.analysis_service import AnalysisService
from app.database.models import Analysis
from app.modules.report_management.pdf_exporter import generate_analysis_pdf

web_bp = Blueprint("web", __name__)
api_bp = Blueprint("api", __name__, url_prefix="/api")

SAMPLE_VULNERABLE_CODE = """import os
import sqlite3
import subprocess
import pickle

# CWE-798: Hardcoded secret token
api_key = "sk_live_51NzSecretKey99887766"

def get_user_record(user_id, cmd_input, raw_payload):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # CWE-89: SQL Injection via f-string interpolation
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

    # CWE-78: OS Command Injection
    os.system("ping -c 1 " + cmd_input)
    subprocess.Popen(cmd_input, shell=True)

    # CWE-95: Arbitrary Code Execution via eval
    result = eval(cmd_input)

    # CWE-502: Unsafe Deserialization
    obj = pickle.loads(raw_payload)

    try:
        conn.commit()
    except:
        pass
    return result
"""

@web_bp.route("/")
def index():
    recent = Analysis.query.order_by(Analysis.created_at.desc()).limit(5).all()
    total_scans = Analysis.query.count()
    avg_quality = 100.0
    if total_scans > 0:
        all_scans = Analysis.query.all()
        avg_quality = round(sum(s.quality_score for s in all_scans) / total_scans, 1)
    return render_template("index.html", recent=recent, total_scans=total_scans, avg_quality=avg_quality)

@web_bp.route("/analyze", methods=["GET", "POST"])
def analyze_page():
    if request.method == "POST":
        filename = request.form.get("filename", "snippet.py").strip() or "snippet.py"
        code = request.form.get("source_code", "")

        uploaded_file = request.files.get("code_file")
        if uploaded_file and uploaded_file.filename:
            filename = uploaded_file.filename
            code = uploaded_file.read().decode("utf-8", errors="replace")

        if not code.strip():
            return render_template("analyze.html", error="Please paste Python code or upload a .py file.", sample_code=SAMPLE_VULNERABLE_CODE)

        record = AnalysisService.run_full_analysis(source_code=code, filename=filename)
        return redirect(url_for("web.results_page", analysis_id=record.id))

    return render_template("analyze.html", sample_code=SAMPLE_VULNERABLE_CODE)

@web_bp.route("/results/<int:analysis_id>")
def results_page(analysis_id: int):
    analysis = Analysis.query.get_or_404(analysis_id)
    return render_template("results.html", analysis=analysis)

@web_bp.route("/history")
def history_page():
    scans = Analysis.query.order_by(Analysis.created_at.desc()).all()
    return render_template("history.html", scans=scans)

@web_bp.route("/reports/<int:analysis_id>/pdf")
def download_pdf(analysis_id: int):
    analysis = Analysis.query.get_or_404(analysis_id)
    pdf_path = generate_analysis_pdf(analysis, current_app.config["REPORT_FOLDER"])
    return send_file(pdf_path, as_attachment=True, download_name=f"Audit_Report_{analysis.filename}_{analysis.id}.pdf")

# REST API Endpoints
@api_bp.route("/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    code = data.get("source_code", "")
    filename = data.get("filename", "api_snippet.py")
    if not code.strip():
        return jsonify({"error": "source_code is required"}), 400
    record = AnalysisService.run_full_analysis(source_code=code, filename=filename)
    return jsonify(record.to_dict()), 201

@api_bp.route("/analyses", methods=["GET"])
def api_history():
    scans = Analysis.query.order_by(Analysis.created_at.desc()).limit(50).all()
    return jsonify([s.to_dict() for s in scans]), 200
''',

    "app/__init__.py": '''import os
from flask import Flask, jsonify
from app.core.config import config_by_name
from app.core.extensions import db, migrate, jwt

def create_app(config_name: str = "development") -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="../frontend/static")
    
    cfg = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(cfg)

    for folder in [app.config["UPLOAD_FOLDER"], app.config["REPORT_FOLDER"], app.config["TEMP_FOLDER"]]:
        os.makedirs(folder, exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    from app.api.routes.analysis_routes import web_bp, api_bp
    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy", "service": "AI-Code-Quality-Platform"}), 200

    return app
''',

    "app/templates/base.html": '''<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeGuard AI — AST Code Quality & Bug Detection Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        body { background-color: #0b0f19; color: #e2e8f0; font-family: 'Inter', system-ui, sans-serif; }
        .glass { background: rgba(17, 24, 39, 0.85); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.08); }
        pre, code { font-family: 'JetBrains Mono', 'Fira Code', monospace; }
    </style>
</head>
<body class="min-h-screen flex flex-col">
    <nav class="glass sticky top-0 z-50 border-b border-slate-800">
        <div class="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
            <a href="/" class="flex items-center space-x-3">
                <div class="w-10 h-10 rounded-lg bg-indigo-600 flex items-center justify-center text-white font-bold text-xl shadow-lg shadow-indigo-500/30">
                    <i class="fa-solid fa-shield-halved"></i>
                </div>
                <div>
                    <span class="text-lg font-bold tracking-tight text-white">CodeGuard <span class="text-indigo-400">AI</span></span>
                    <span class="block text-xs text-slate-400">AST-Guided Security & Quality Engine</span>
                </div>
            </a>
            <div class="flex items-center space-x-6 text-sm font-medium">
                <a href="/" class="hover:text-indigo-400 transition"><i class="fa-solid fa-chart-pie mr-1.5"></i>Dashboard</a>
                <a href="/analyze" class="hover:text-indigo-400 transition"><i class="fa-solid fa-microscope mr-1.5"></i>New Scan</a>
                <a href="/history" class="hover:text-indigo-400 transition"><i class="fa-solid fa-clock-rotate-left mr-1.5"></i>Scan History</a>
                <a href="/analyze" class="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg shadow transition">
                    <i class="fa-solid fa-bolt mr-1"></i> Analyze Code
                </a>
            </div>
        </div>
    </nav>

    <main class="flex-grow max-w-7xl w-full mx-auto px-6 py-8">
        {% block content %}{% endblock %}
    </main>

    <footer class="border-t border-slate-800/80 py-6 text-center text-xs text-slate-500">
        AI-Powered Code Quality & Bug Detection Platform • Hybrid AST + CWE Taxonomy + TF-IDF Naive Bayes Triage
    </footer>
</body>
</html>
''',

    "app/templates/index.html": '''{% extends "base.html" %}
{% block content %}
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
    <div class="lg:col-span-2 glass rounded-2xl p-8 border border-indigo-500/20">
        <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 mb-4">
            <i class="fa-solid fa-code-branch mr-1.5"></i> Hybrid Static AST + Machine Learning Pipeline
        </span>
        <h1 class="text-3xl font-extrabold text-white mb-3">Enterprise Code Quality & Automated Vulnerability Remediation</h1>
        <p class="text-slate-400 text-sm leading-relaxed mb-6">
            Scan Python source files for CWE security vulnerabilities (SQLi, Command Injection, RCE, Hardcoded Secrets), Cyclomatic Complexity bottlenecks, and Maintainability scores—complete with automated unified git diff patches.
        </p>
        <div class="flex space-x-4">
            <a href="/analyze" class="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-6 py-3 rounded-xl shadow-lg shadow-indigo-600/30 transition">
                <i class="fa-solid fa-play mr-2"></i> Launch Code Scanner
            </a>
            <a href="/history" class="bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-6 py-3 rounded-xl border border-slate-700 transition">
                View Audit Logs
            </a>
        </div>
    </div>

    <div class="glass rounded-2xl p-6 flex flex-col justify-between">
        <div>
            <h3 class="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">Platform Telemetry</h3>
            <div class="grid grid-cols-2 gap-4">
                <div class="bg-slate-900/90 p-4 rounded-xl border border-slate-800">
                    <span class="text-xs text-slate-400">Total Scans</span>
                    <p class="text-2xl font-bold text-white mt-1">{{ total_scans }}</p>
                </div>
                <div class="bg-slate-900/90 p-4 rounded-xl border border-slate-800">
                    <span class="text-xs text-slate-400">Avg Quality</span>
                    <p class="text-2xl font-bold text-emerald-400 mt-1">{{ avg_quality }}%</p>
                </div>
            </div>
        </div>
        <div class="mt-6 pt-4 border-t border-slate-800 text-xs text-slate-400 space-y-1.5">
            <div><i class="fa-solid fa-check text-emerald-400 mr-2"></i>AST Node & Call-Site CWE Mapping</div>
            <div><i class="fa-solid fa-check text-emerald-400 mr-2"></i>Radon Cyclomatic Complexity & MI</div>
            <div><i class="fa-solid fa-check text-emerald-400 mr-2"></i>Automated Unified Diff (.patch) Synthesis</div>
        </div>
    </div>
</div>

<div class="glass rounded-2xl p-6">
    <div class="flex justify-between items-center mb-4">
        <h2 class="text-lg font-bold text-white"><i class="fa-solid fa-list-check text-indigo-400 mr-2"></i>Recent Code Audits</h2>
        <a href="/history" class="text-xs text-indigo-400 hover:underline">View All &rarr;</a>
    </div>
    {% if recent %}
    <div class="overflow-x-auto">
        <table class="w-full text-left text-sm">
            <thead class="text-xs uppercase text-slate-400 border-b border-slate-800">
                <tr>
                    <th class="py-3 px-4">ID</th>
                    <th class="py-3 px-4">File</th>
                    <th class="py-3 px-4">Quality Score</th>
                    <th class="py-3 px-4">Security Score</th>
                    <th class="py-3 px-4">Issues Found</th>
                    <th class="py-3 px-4">Action</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
                {% for item in recent %}
                <tr class="hover:bg-slate-800/40 transition">
                    <td class="py-3 px-4 font-mono text-xs text-slate-400">#{{ item.id }}</td>
                    <td class="py-3 px-4 font-medium text-white">{{ item.filename }}</td>
                    <td class="py-3 px-4">
                        <span class="px-2.5 py-1 rounded-md text-xs font-bold {% if item.quality_score >= 75 %}bg-emerald-500/10 text-emerald-400{% elif item.quality_score >= 50 %}bg-amber-500/10 text-amber-400{% else %}bg-rose-500/10 text-rose-400{% endif %}">
                            {{ item.quality_score }} / 100
                        </span>
                    </td>
                    <td class="py-3 px-4">
                        <span class="px-2.5 py-1 rounded-md text-xs font-bold {% if item.security_score >= 80 %}bg-emerald-500/10 text-emerald-400{% else %}bg-rose-500/10 text-rose-400{% endif %}">
                            {{ item.security_score }} / 100
                        </span>
                    </td>
                    <td class="py-3 px-4 text-slate-300">{{ item.bugs|length }} issues</td>
                    <td class="py-3 px-4">
                        <a href="/results/{{ item.id }}" class="text-indigo-400 hover:text-indigo-300 text-xs font-semibold">Inspect Report &rarr;</a>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% else %}
    <p class="text-slate-400 text-sm py-6 text-center">No scans recorded yet. Click <b>Analyze Code</b> to run your first audit!</p>
    {% endif %}
</div>
{% endblock %}
''',

    "app/templates/analyze.html": '''{% extends "base.html" %}
{% block content %}
<div class="max-w-5xl mx-auto">
    <div class="mb-6 flex justify-between items-end">
        <div>
            <h1 class="text-2xl font-bold text-white">AST Code Quality & Vulnerability Scanner</h1>
            <p class="text-sm text-slate-400">Paste source code or upload a Python file for deep AST + CWE + ML defect inspection.</p>
        </div>
        <button type="button" onclick="loadDemoCode()" class="text-xs bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 px-3 py-2 rounded-lg transition">
            <i class="fa-solid fa-flask mr-1"></i> Load Vulnerable Demo Snippet
        </button>
    </div>

    {% if error %}
    <div class="mb-6 bg-rose-500/10 border border-rose-500/30 text-rose-300 px-4 py-3 rounded-xl text-sm">
        <i class="fa-solid fa-triangle-exclamation mr-2"></i>{{ error }}
    </div>
    {% endif %}

    <form method="POST" action="/analyze" enctype="multipart/form-data" class="glass rounded-2xl p-6 space-y-6">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
                <label class="block text-xs font-semibold uppercase text-slate-400 mb-2">Target Filename</label>
                <input type="text" name="filename" value="payment_service.py" class="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-indigo-500">
            </div>
            <div>
                <label class="block text-xs font-semibold uppercase text-slate-400 mb-2">Or Upload Python File (.py)</label>
                <input type="file" name="code_file" accept=".py" class="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2 text-sm text-slate-300 file:mr-4 file:py-1 file:px-3 file:rounded-lg file:border-0 file:text-xs file:bg-indigo-600 file:text-white">
            </div>
        </div>

        <div>
            <label class="block text-xs font-semibold uppercase text-slate-400 mb-2">Source Code Editor</label>
            <textarea id="codeEditor" name="source_code" rows="16" class="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-sm text-emerald-300 focus:outline-none focus:border-indigo-500 leading-relaxed" placeholder="Paste Python code here...">{{ sample_code }}</textarea>
        </div>

        <div class="flex justify-end">
            <button type="submit" class="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-8 py-3 rounded-xl shadow-lg shadow-indigo-600/30 transition">
                <i class="fa-solid fa-magnifying-glass-chart mr-2"></i> Run Full AST & Security Audit
            </button>
        </div>
    </form>
</div>

<script>
const DEMO_SNIPPET = {{ sample_code|tojson }};
function loadDemoCode() {
    document.getElementById("codeEditor").value = DEMO_SNIPPET;
}
</script>
{% endblock %}
''',

    "app/templates/results.html": '''{% extends "base.html" %}
{% block content %}
<div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
    <div>
        <div class="flex items-center space-x-3">
            <span class="px-3 py-1 rounded-full text-xs font-mono bg-slate-800 text-indigo-400 border border-slate-700">Audit #{{ analysis.id }}</span>
            <h1 class="text-2xl font-bold text-white">{{ analysis.filename }}</h1>
        </div>
        <p class="text-xs text-slate-400 mt-1">Scanned on {{ analysis.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') }} • {{ analysis.loc }} Lines of Code</p>
    </div>
    <div class="flex space-x-3">
        <a href="/reports/{{ analysis.id }}/pdf" class="bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold px-4 py-2.5 rounded-xl shadow transition">
            <i class="fa-solid fa-file-pdf mr-1.5"></i> Export PDF Report
        </a>
        <a href="/analyze" class="bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-semibold px-4 py-2.5 rounded-xl border border-slate-700 transition">
            New Scan
        </a>
    </div>
</div>

<!-- Telemetry Cards -->
<div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
    <div class="glass p-4 rounded-xl">
        <span class="text-xs text-slate-400">Overall Quality</span>
        <p class="text-2xl font-extrabold mt-1 {% if analysis.quality_score >= 75 %}text-emerald-400{% elif analysis.quality_score >= 50 %}text-amber-400{% else %}text-rose-400{% endif %}">
            {{ analysis.quality_score }}<span class="text-xs font-normal text-slate-500">/100</span>
        </p>
    </div>
    <div class="glass p-4 rounded-xl">
        <span class="text-xs text-slate-400">Security Score</span>
        <p class="text-2xl font-extrabold mt-1 {% if analysis.security_score >= 80 %}text-emerald-400{% else %}text-rose-400{% endif %}">
            {{ analysis.security_score }}<span class="text-xs font-normal text-slate-500">/100</span>
        </p>
    </div>
    <div class="glass p-4 rounded-xl">
        <span class="text-xs text-slate-400">Maintainability Index</span>
        <p class="text-2xl font-extrabold text-indigo-400 mt-1">{{ analysis.maintainability_index }}</p>
    </div>
    <div class="glass p-4 rounded-xl">
        <span class="text-xs text-slate-400">Cyclomatic Complexity</span>
        <p class="text-2xl font-extrabold text-sky-400 mt-1">{{ analysis.cyclomatic_complexity }}</p>
    </div>
    <div class="glass p-4 rounded-xl">
        <span class="text-xs text-slate-400">ML Defect Probability</span>
        <p class="text-2xl font-extrabold text-amber-400 mt-1">{{ (analysis.ml_bug_probability * 100)|round(1) }}%</p>
    </div>
</div>

<!-- Findings & Unified Patch Diffs -->
<div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
    <div class="lg:col-span-7 space-y-4">
        <h2 class="text-lg font-bold text-white mb-2">
            <i class="fa-solid fa-bug text-rose-400 mr-2"></i>Detected Vulnerabilities & AST Findings ({{ analysis.bugs|length }})
        </h2>

        {% if not analysis.bugs %}
        <div class="glass rounded-2xl p-8 text-center border border-emerald-500/30">
            <i class="fa-solid fa-circle-check text-4xl text-emerald-400 mb-3"></i>
            <h3 class="text-lg font-bold text-white">Zero Vulnerabilities Detected!</h3>
            <p class="text-sm text-slate-400 mt-1">This file passed all AST security checks and complexity gates.</p>
        </div>
        {% else %}
            {% for bug in analysis.bugs %}
            <div class="glass rounded-2xl p-5 border-l-4 {% if bug.severity == 'Critical' %}border-rose-500{% elif bug.severity == 'High' %}border-orange-500{% elif bug.severity == 'Medium' %}border-amber-400{% else %}border-sky-400{% endif %}">
                <div class="flex justify-between items-start mb-2">
                    <div class="flex items-center space-x-2">
                        <span class="px-2.5 py-0.5 rounded text-xs font-bold uppercase {% if bug.severity == 'Critical' %}bg-rose-500/20 text-rose-300{% elif bug.severity == 'High' %}bg-orange-500/20 text-orange-300{% else %}bg-amber-500/20 text-amber-300{% endif %}">
                            {{ bug.severity }}
                        </span>
                        {% if bug.cwe_id %}
                        <span class="px-2.5 py-0.5 rounded text-xs font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                            {{ bug.cwe_id }}
                        </span>
                        {% endif %}
                        <span class="text-xs text-slate-400 font-mono">Line {{ bug.line_number }} • fn: {{ bug.function_name }}</span>
                    </div>
                </div>

                <h3 class="text-base font-bold text-white mb-1">{{ bug.title }}</h3>
                <p class="text-xs text-slate-300 mb-3">{{ bug.description }}</p>

                {% if bug.code_snippet %}
                <div class="mb-3">
                    <span class="text-[11px] uppercase font-semibold text-slate-400">Vulnerable AST Node:</span>
                    <pre class="bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-rose-300 overflow-x-auto mt-1">{{ bug.code_snippet }}</pre>
                </div>
                {% endif %}

                <div class="bg-indigo-950/30 border border-indigo-500/20 rounded-lg p-3 mb-3">
                    <span class="text-xs font-semibold text-indigo-300"><i class="fa-solid fa-wrench mr-1"></i>Remediation Guidance:</span>
                    <p class="text-xs text-slate-300 mt-0.5">{{ bug.recommendation }}</p>
                </div>

                {% if bug.patch_diff %}
                <div>
                    <span class="text-[11px] uppercase font-semibold text-emerald-400"><i class="fa-solid fa-code-commit mr-1"></i>Synthesized Git Unified Diff (.patch):</span>
                    <pre class="bg-slate-950 border border-emerald-500/30 rounded-lg p-3 text-xs text-emerald-300 overflow-x-auto mt-1">{{ bug.patch_diff }}</pre>
                </div>
                {% endif %}
            </div>
            {% endfor %}
        {% endif %}
    </div>

    <!-- Annotated Source Code Panel -->
    <div class="lg:col-span-5">
        <h2 class="text-lg font-bold text-white mb-2"><i class="fa-solid fa-file-code text-indigo-400 mr-2"></i>Inspected Source Code</h2>
        <div class="glass rounded-2xl p-4 overflow-x-auto">
            <pre class="text-xs leading-6 font-mono text-slate-300">{% for line in analysis.source_code.splitlines() %}<span class="text-slate-600 select-none mr-4">{{ "%3d"|format(loop.index) }} |</span>{{ line }}
{% endfor %}</pre>
        </div>
    </div>
</div>
{% endblock %}
''',

    "app/templates/history.html": '''{% extends "base.html" %}
{% block content %}
<div class="glass rounded-2xl p-6">
    <div class="flex justify-between items-center mb-6">
        <div>
            <h1 class="text-2xl font-bold text-white">Complete Audit History</h1>
            <p class="text-xs text-slate-400">Archive of all AST code quality and CWE vulnerability scans</p>
        </div>
        <a href="/analyze" class="bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold px-4 py-2 rounded-xl transition">
            + New Scan
        </a>
    </div>

    <div class="overflow-x-auto">
        <table class="w-full text-left text-sm">
            <thead class="text-xs uppercase text-slate-400 border-b border-slate-800">
                <tr>
                    <th class="py-3 px-4">Audit ID</th>
                    <th class="py-3 px-4">Filename</th>
                    <th class="py-3 px-4">LOC</th>
                    <th class="py-3 px-4">Quality</th>
                    <th class="py-3 px-4">Security</th>
                    <th class="py-3 px-4">Complexity</th>
                    <th class="py-3 px-4">Findings</th>
                    <th class="py-3 px-4">Timestamp</th>
                    <th class="py-3 px-4">Report</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
                {% for s in scans %}
                <tr class="hover:bg-slate-800/40 transition">
                    <td class="py-3 px-4 font-mono text-xs text-indigo-400">#{{ s.id }}</td>
                    <td class="py-3 px-4 font-semibold text-white">{{ s.filename }}</td>
                    <td class="py-3 px-4 text-slate-400">{{ s.loc }}</td>
                    <td class="py-3 px-4 font-bold text-emerald-400">{{ s.quality_score }}</td>
                    <td class="py-3 px-4 font-bold text-rose-400">{{ s.security_score }}</td>
                    <td class="py-3 px-4 text-slate-300">{{ s.cyclomatic_complexity }}</td>
                    <td class="py-3 px-4">{{ s.bugs|length }} bugs</td>
                    <td class="py-3 px-4 text-xs text-slate-400">{{ s.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
                    <td class="py-3 px-4 space-x-3">
                        <a href="/results/{{ s.id }}" class="text-indigo-400 hover:underline text-xs font-semibold">View</a>
                        <a href="/reports/{{ s.id }}/pdf" class="text-emerald-400 hover:underline text-xs font-semibold">PDF</a>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
{% endblock %}
'''
}

for filepath, content in FILES_CONTENT.items():
    p = Path(filepath)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    print(f"Populated: {filepath}")

print("\nAll Step 5 & Step 6 API, PDF Report, and Frontend UI files written successfully!")