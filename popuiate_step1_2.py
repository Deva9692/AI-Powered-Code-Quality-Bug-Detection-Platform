from pathlib import Path

FILES_CONTENT = {
    "app/core/config.py": '''import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-fallback")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-jwt-key-fallback")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "storage", "uploads")
    REPORT_FOLDER = os.path.join(BASE_DIR, "storage", "generated_reports")
    TEMP_FOLDER = os.path.join(BASE_DIR, "storage", "temp")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{BASE_DIR / 'storage' / 'app_dev.db'}"

config_by_name = {
    "development": DevelopmentConfig,
    "default": DevelopmentConfig,
}
''',

    "app/core/extensions.py": '''from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
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

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy", "service": "AI-Code-Quality-Platform"}), 200

    return app
''',

    "run.py": '''import os
from dotenv import load_dotenv
from app import create_app

load_dotenv()

env = os.getenv("FLASK_ENV", "development")
app = create_app(env)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
''',

    "app/database/models/user.py": '''from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from app.core.extensions import db

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="developer")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    analyses = db.relationship("Analysis", backref="author", lazy="dynamic", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat()
        }
''',

    "app/database/models/analysis.py": '''from datetime import datetime, timezone
from app.core.extensions import db

class Analysis(db.Model):
    __tablename__ = "analyses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    filename = db.Column(db.String(255), nullable=False, default="snippet.py")
    language = db.Column(db.String(50), nullable=False, default="python")
    source_code = db.Column(db.Text, nullable=False)
    
    loc = db.Column(db.Integer, default=0)
    cyclomatic_complexity = db.Column(db.Float, default=0.0)
    maintainability_index = db.Column(db.Float, default=100.0)
    quality_score = db.Column(db.Float, default=100.0)
    security_score = db.Column(db.Float, default=100.0)
    ml_bug_probability = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(30), default="completed")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    bugs = db.relationship("Bug", backref="analysis", lazy="joined", cascade="all, delete-orphan")
    report = db.relationship("Report", backref="analysis", uselist=False, cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "filename": self.filename,
            "language": self.language,
            "loc": self.loc,
            "cyclomatic_complexity": round(self.cyclomatic_complexity, 2),
            "maintainability_index": round(self.maintainability_index, 2),
            "quality_score": round(self.quality_score, 2),
            "security_score": round(self.security_score, 2),
            "ml_bug_probability": round(self.ml_bug_probability, 4),
            "bug_count": len(self.bugs),
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "bugs": [b.to_dict() for b in self.bugs]
        }
''',

    "app/database/models/bug.py": '''from app.core.extensions import db

class Bug(db.Model):
    __tablename__ = "bugs"

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analyses.id"), nullable=False, index=True)
    
    cwe_id = db.Column(db.String(30), nullable=True)
    category = db.Column(db.String(64), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    line_number = db.Column(db.Integer, nullable=True)
    function_name = db.Column(db.String(120), nullable=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    code_snippet = db.Column(db.Text, nullable=True)
    recommendation = db.Column(db.Text, nullable=True)
    patch_diff = db.Column(db.Text, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cwe_id": self.cwe_id,
            "category": self.category,
            "severity": self.severity,
            "line_number": self.line_number,
            "function_name": self.function_name,
            "title": self.title,
            "description": self.description,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "patch_diff": self.patch_diff
        }
''',

    "app/database/models/report.py": '''from datetime import datetime, timezone
from app.core.extensions import db

class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analyses.id"), nullable=False, unique=True)
    report_title = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=True)
    summary_text = db.Column(db.Text, nullable=True)
    generated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "analysis_id": self.analysis_id,
            "report_title": self.report_title,
            "file_path": self.file_path,
            "summary_text": self.summary_text,
            "generated_at": self.generated_at.isoformat()
        }
''',

    "app/database/models/__init__.py": '''from app.database.models.user import User
from app.database.models.analysis import Analysis
from app.database.models.bug import Bug
from app.database.models.report import Report

__all__ = ["User", "Analysis", "Bug", "Report"]
''',
 
    "scripts/init_db.py": '''import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.core.extensions import db
from app.database.models import User, Analysis, Bug, Report

def initialize_database():
    app = create_app("development")
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            demo_user = User(username="admin", email="admin@codequality.ai", role="admin")
            demo_user.set_password("Admin@123")
            db.session.add(demo_user)
            db.session.commit()
            print("Default user created: admin@codequality.ai / Admin@123")
        print("Database tables initialized successfully in storage/app_dev.db!")

if __name__ == "__main__":
    initialize_database()
'''
}

for filepath, content in FILES_CONTENT.items():
    p = Path(filepath)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    print(f"Populated: {filepath}")

print("\nAll Step 1 & Step 2 files written successfully!")