from pathlib import Path

FILES_CONTENT = {
    "app/modules/code_analysis/syntax_checker.py": '''import ast
from typing import Dict, Any

def check_syntax(source_code: str) -> Dict[str, Any]:
    """Validates Python syntax using the built-in AST parser."""
    try:
        tree = ast.parse(source_code)
        return {"valid": True, "tree": tree, "error": None}
    except SyntaxError as e:
        return {
            "valid": False,
            "tree": None,
            "error": {
                "cwe_id": "SYNTAX-ERR",
                "category": "Syntax",
                "severity": "Critical",
                "line_number": e.lineno or 1,
                "function_name": "<module>",
                "title": f"SyntaxError: {e.msg}",
                "description": f"Invalid Python syntax at line {e.lineno}, column {e.offset}: {e.msg}",
                "code_snippet": (e.text or "").strip(),
                "recommendation": "Fix the syntax error before executing static and security passes.",
                "patch_diff": None
            }
        }
''',

    "app/modules/code_analysis/parser.py": '''import ast
from typing import Dict, Any, List

class ASTStructureExtractor(ast.NodeVisitor):
    """Extracts functions, classes, imports, and line mappings from an AST."""
    def __init__(self):
        self.functions: List[Dict[str, Any]] = []
        self.classes: List[Dict[str, Any]] = []
        self.imports: List[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.functions.append({
            "name": node.name,
            "line_start": node.lineno,
            "line_end": getattr(node, "end_lineno", node.lineno),
            "args": [arg.arg for arg in node.args.args]
        })
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.classes.append({
            "name": node.name,
            "line_start": node.lineno,
            "line_end": getattr(node, "end_lineno", node.lineno)
        })
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            self.imports.append(f"{module}.{alias.name}" if module else alias.name)
        self.generic_visit(node)

def extract_ast_metadata(tree: ast.AST) -> Dict[str, Any]:
    extractor = ASTStructureExtractor()
    extractor.visit(tree)
    return {
        "functions": extractor.functions,
        "classes": extractor.classes,
        "imports": extractor.imports
    }
''',

    "app/modules/code_analysis/complexity_analyzer.py": '''from typing import Dict, Any, List
from radon.complexity import cc_visit
from radon.metrics import mi_visit
from radon.raw import analyze as raw_analyze

def analyze_complexity(source_code: str) -> Dict[str, Any]:
    """Calculates LOC, Cyclomatic Complexity, and Maintainability Index."""
    try:
        raw_metrics = raw_analyze(source_code)
        cc_blocks = cc_visit(source_code)
        mi_score = mi_visit(source_code, multi=True)

        avg_cc = sum(b.complexity for b in cc_blocks) / len(cc_blocks) if cc_blocks else 1.0
        complexity_bugs: List[Dict[str, Any]] = []

        for block in cc_blocks:
            if block.complexity >= 10:
                severity = "High" if block.complexity >= 15 else "Medium"
                complexity_bugs.append({
                    "cwe_id": "CWE-1121",
                    "category": "Complexity",
                    "severity": severity,
                    "line_number": block.lineno,
                    "function_name": block.name,
                    "title": f"Excessive Cyclomatic Complexity ({block.complexity}) in '{block.name}'",
                    "description": (
                        f"Function '{block.name}' has a cyclomatic complexity of {block.complexity}, "
                        "exceeding the recommended threshold of 10. High complexity increases defect risk."
                    ),
                    "code_snippet": f"def {block.name}(...):",
                    "recommendation": "Refactor nested conditionals into smaller helper functions or guard clauses.",
                    "patch_diff": None
                })

        return {
            "loc": raw_metrics.loc,
            "lloc": raw_metrics.lloc,
            "cyclomatic_complexity": round(avg_cc, 2),
            "maintainability_index": round(float(mi_score), 2),
            "complexity_findings": complexity_bugs
        }
    except Exception:
        lines = [line for line in source_code.splitlines() if line.strip()]
        return {
            "loc": len(lines),
            "lloc": len(lines),
            "cyclomatic_complexity": 1.0,
            "maintainability_index": 85.0,
            "complexity_findings": []
        }
''',

    "app/modules/security_analysis/security_scanner.py": '''import ast
import re
from typing import List, Dict, Any

def make_unified_patch(filename: str, line_no: int, old_line: str, new_line: str) -> str:
    """Synthesizes a standard git unified diff patch."""
    indent = len(old_line) - len(old_line.lstrip())
    spaces = " " * indent
    return (
        f"--- a/{filename}\\n"
        f"+++ b/{filename}\\n"
        f"@@ -{line_no},1 +{line_no},1 @@\\n"
        f"-{old_line}\\n"
        f"+{spaces}{new_line.strip()}"
    )

class ASTSecurityScanner(ast.NodeVisitor):
    """AST-Guided Vulnerability Detector with CWE Taxonomy Mapping and Patch Synthesis."""
    def __init__(self, source_code: str, filename: str = "snippet.py"):
        self.lines = source_code.splitlines()
        self.filename = filename
        self.findings: List[Dict[str, Any]] = []
        self.current_function = "<module>"

    def _get_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1]
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev

    def visit_Assign(self, node: ast.Assign):
        # CWE-798: Use of Hard-coded Credentials
        secret_pattern = re.compile(r"(password|passwd|secret|api_key|token|private_key)", re.IGNORECASE)
        for target in node.targets:
            if isinstance(target, ast.Name) and secret_pattern.search(target.id):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) > 2:
                    raw_line = self._get_line(node.lineno)
                    env_var = target.id.upper()
                    fixed_line = f'{target.id} = os.getenv("{env_var}")'
                    self.findings.append({
                        "cwe_id": "CWE-798",
                        "category": "Security",
                        "severity": "Critical",
                        "line_number": node.lineno,
                        "function_name": self.current_function,
                        "title": f"Hardcoded Credential in Variable '{target.id}'",
                        "description": "Sensitive secret or credential is hardcoded directly in source code.",
                        "code_snippet": raw_line.strip(),
                        "recommendation": f"Load '{target.id}' securely from environment variables using os.getenv('{env_var}').",
                        "patch_diff": make_unified_patch(self.filename, node.lineno, raw_line, fixed_line)
                    })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        raw_line = self._get_line(node.lineno)
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = f"{ getattr(node.func.value, 'id', '') }.{node.func.attr}"

        # 1. CWE-95: Eval / Exec Dynamic Code Execution
        if func_name in ("eval", "exec"):
            fixed_line = raw_line.replace(f"{func_name}(", "ast.literal_eval(")
            self.findings.append({
                "cwe_id": "CWE-95",
                "category": "Security",
                "severity": "Critical",
                "line_number": node.lineno,
                "function_name": self.current_function,
                "title": f"Arbitrary Code Execution via '{func_name}()'",
                "description": f"Calling {func_name}() on untrusted input allows remote code execution (RCE).",
                "code_snippet": raw_line.strip(),
                "recommendation": "Replace eval() with ast.literal_eval() or JSON parsing.",
                "patch_diff": make_unified_patch(self.filename, node.lineno, raw_line, fixed_line)
            })

        # 2. CWE-78: OS Command Injection
        if func_name in ("os.system", "os.popen"):
            self.findings.append({
                "cwe_id": "CWE-78",
                "category": "Security",
                "severity": "Critical",
                "line_number": node.lineno,
                "function_name": self.current_function,
                "title": f"OS Command Injection Sink ('{func_name}')",
                "description": "Executing shell commands via os.system exposes the host to command injection.",
                "code_snippet": raw_line.strip(),
                "recommendation": "Use subprocess.run([cmd, arg1], shell=False, check=True) with an argument list.",
                "patch_diff": make_unified_patch(
                    self.filename, node.lineno, raw_line,
                    "subprocess.run(shlex.split(command), shell=False, check=True)"
                )
            })

        if func_name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    fixed_line = raw_line.replace("shell=True", "shell=False")
                    self.findings.append({
                        "cwe_id": "CWE-78",
                        "category": "Security",
                        "severity": "High",
                        "line_number": node.lineno,
                        "function_name": self.current_function,
                        "title": "Subprocess Invoked with 'shell=True'",
                        "description": "Spawning a shell with user-controlled input permits shell metacharacter injection.",
                        "code_snippet": raw_line.strip(),
                        "recommendation": "Pass arguments as a sequence list and set shell=False.",
                        "patch_diff": make_unified_patch(self.filename, node.lineno, raw_line, fixed_line)
                    })

        # 3. CWE-89: SQL Injection in cursor.execute / session.execute
        if func_name.endswith(".execute") and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, (ast.JoinedStr, ast.BinOp, ast.Call)):
                self.findings.append({
                    "cwe_id": "CWE-89",
                    "category": "Security",
                    "severity": "Critical",
                    "line_number": node.lineno,
                    "function_name": self.current_function,
                    "title": "SQL Injection via Dynamic String Interpolation",
                    "description": "SQL query is dynamically constructed using f-strings, % formatting, or concatenation.",
                    "code_snippet": raw_line.strip(),
                    "recommendation": "Use parameterized queries with placeholders (?, %s) and pass parameters as a tuple.",
                    "patch_diff": make_unified_patch(
                        self.filename, node.lineno, raw_line,
                        'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
                    )
                })

        # 4. CWE-502: Deserialization of Untrusted Data
        if func_name in ("pickle.loads", "pickle.load", "yaml.load"):
            fixed_line = raw_line.replace("yaml.load(", "yaml.safe_load(").replace("pickle.loads(", "json.loads(")
            self.findings.append({
                "cwe_id": "CWE-502",
                "category": "Security",
                "severity": "High",
                "line_number": node.lineno,
                "function_name": self.current_function,
                "title": f"Insecure Deserialization ('{func_name}')",
                "description": "Deserializing untrusted payloads via pickle or unsafe yaml.load can trigger arbitrary execution.",
                "code_snippet": raw_line.strip(),
                "recommendation": "Use json.loads() or yaml.safe_load() instead of unsafe deserializers.",
                "patch_diff": make_unified_patch(self.filename, node.lineno, raw_line, fixed_line)
            })

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        # CWE-396 / Logic Bug: Bare Except or Swallowed Exception
        if node.type is None:
            raw_line = self._get_line(node.lineno)
            self.findings.append({
                "cwe_id": "CWE-396",
                "category": "Logic",
                "severity": "Medium",
                "line_number": node.lineno,
                "function_name": self.current_function,
                "title": "Bare 'except:' Clause Masks Critical Errors",
                "description": "Catching all exceptions without specifying Exception type hides system interrupts and bugs.",
                "code_snippet": raw_line.strip(),
                "recommendation": "Specify 'except Exception as e:' and log the error properly.",
                "patch_diff": make_unified_patch(self.filename, node.lineno, raw_line, "except Exception as e:")
            })
        self.generic_visit(node)

def run_security_scan(tree: ast.AST, source_code: str, filename: str = "snippet.py") -> List[Dict[str, Any]]:
    scanner = ASTSecurityScanner(source_code, filename)
    scanner.visit(tree)
    return scanner.findings
''',

    "ml/training/train.py": '''import os
from pathlib import Path
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = BASE_DIR / "ml" / "models"

TRAINING_DATA = [
    # Vulnerable / Buggy code samples (Label = 1)
    ('cursor.execute(f"SELECT * FROM users WHERE username = {user}")', 1),
    ('os.system("rm -rf " + user_input)', 1),
    ('subprocess.Popen(cmd, shell=True)', 1),
    ('eval(request.args.get("code"))', 1),
    ('exec(user_supplied_script)', 1),
    ('password = "SuperSecretAdmin123"', 1),
    ('api_key = "sk_live_9988776655"', 1),
    ('pickle.loads(raw_payload)', 1),
    ('yaml.load(stream)', 1),
    ('except:\n    pass', 1),
    ('query = "DELETE FROM accounts WHERE id=" + str(uid)', 1),
    ('hashlib.md5(password.encode())', 1),

    # Clean / Safe code samples (Label = 0)
    ('cursor.execute("SELECT * FROM users WHERE username = ?", (user,))', 0),
    ('subprocess.run(["ls", "-la"], shell=False, check=True)', 0),
    ('ast.literal_eval(safe_string)', 0),
    ('password = os.getenv("DB_PASSWORD")', 0),
    ('api_key = os.environ.get("STRIPE_API_KEY")', 0),
    ('json.loads(raw_payload)', 0),
    ('yaml.safe_load(stream)', 0),
    ('except ValueError as err:\n    logger.error(err)', 0),
    ('def calculate_average(numbers: list) -> float:\n    return sum(numbers) / len(numbers)', 0),
    ('hashlib.sha256(password.encode()).hexdigest()', 0),
    ('with open("config.json", "r", encoding="utf-8") as f:\n    data = json.load(f)', 0),
    ('return jsonify({"status": "ok", "count": len(items)}), 200', 0),
]

def train_and_save():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]

    vectorizer = TfidfVectorizer(ngram_range=(1, 2), token_pattern=r"(?u)\\b\\w+\\b")
    X = vectorizer.fit_transform(texts)

    clf = MultinomialNB(alpha=0.5)
    clf.fit(X, labels)

    joblib.dump(clf, MODEL_DIR / "bug_model.pkl")
    joblib.dump(vectorizer, MODEL_DIR / "vectorizer.pkl")
    print(f"Trained TF-IDF + Naive Bayes Bug Classifier saved to {MODEL_DIR}")

if __name__ == "__main__":
    train_and_save()
''',

    "app/modules/ai_engine/predictor.py": '''from pathlib import Path
import joblib

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
MODEL_PATH = BASE_DIR / "ml" / "models" / "bug_model.pkl"
VEC_PATH = BASE_DIR / "ml" / "models" / "vectorizer.pkl"

class MLBugPredictor:
    _model = None
    _vectorizer = None

    @classmethod
    def _load(cls):
        if cls._model is None or cls._vectorizer is None:
            if MODEL_PATH.exists() and VEC_PATH.exists():
                cls._model = joblib.load(MODEL_PATH)
                cls._vectorizer = joblib.load(VEC_PATH)

    @classmethod
    def predict_defect_probability(cls, source_code: str) -> float:
        cls._load()
        if cls._model is None or cls._vectorizer is None:
            return 0.15
        features = cls._vectorizer.transform([source_code])
        proba = cls._model.predict_proba(features)[0][1]
        return round(float(proba), 4)
''',

    "app/modules/quality_analysis/quality_scorer.py": '''from typing import List, Dict, Any

SEVERITY_PENALTIES = {
    "Critical": 25.0,
    "High": 15.0,
    "Medium": 8.0,
    "Low": 3.0
}

def compute_scores(
    maintainability_index: float,
    cyclomatic_complexity: float,
    bugs: List[Dict[str, Any]],
    ml_probability: float
) -> Dict[str, float]:
    """Computes composite Security Score and Overall Code Quality Score (0 - 100)."""
    security_bugs = [b for b in bugs if b.get("category") == "Security"]
    sec_penalty = sum(SEVERITY_PENALTIES.get(b.get("severity", "Low"), 5.0) for b in security_bugs)
    security_score = max(0.0, min(100.0, 100.0 - sec_penalty))

    total_bug_penalty = sum(SEVERITY_PENALTIES.get(b.get("severity", "Low"), 5.0) for b in bugs)
    cc_penalty = max(0.0, (cyclomatic_complexity - 5.0) * 2.5)
    ml_penalty = ml_probability * 15.0

    raw_quality = (0.45 * maintainability_index) + (0.55 * (100.0 - total_bug_penalty)) - cc_penalty - ml_penalty
    quality_score = max(0.0, min(100.0, raw_quality))

    return {
        "security_score": round(security_score, 2),
        "quality_score": round(quality_score, 2)
    }
''',

    "app/services/analysis_service.py": '''from typing import Dict, Any, Optional
from app.core.extensions import db
from app.database.models import Analysis, Bug
from app.modules.code_analysis.syntax_checker import check_syntax
from app.modules.code_analysis.parser import extract_ast_metadata
from app.modules.code_analysis.complexity_analyzer import analyze_complexity
from app.modules.security_analysis.security_scanner import run_security_scan
from app.modules.ai_engine.predictor import MLBugPredictor
from app.modules.quality_analysis.quality_scorer import compute_scores

class AnalysisService:
    @staticmethod
    def run_full_analysis(
        source_code: str,
        filename: str = "snippet.py",
        user_id: Optional[int] = None
    ) -> Analysis:
        """Master orchestrator: AST Syntax -> Complexity -> CWE Security -> ML Triage -> DB Persistence."""
        syntax_res = check_syntax(source_code)
        all_findings = []

        if not syntax_res["valid"]:
            all_findings.append(syntax_res["error"])
            loc = len(source_code.splitlines())
            cc_score = 0.0
            mi_score = 0.0
            ml_prob = 0.95
            scores = {"security_score": 100.0, "quality_score": 10.0}
        else:
            tree = syntax_res["tree"]
            _ = extract_ast_metadata(tree)
            comp_res = analyze_complexity(source_code)
            sec_findings = run_security_scan(tree, source_code, filename)

            all_findings.extend(sec_findings)
            all_findings.extend(comp_res["complexity_findings"])

            loc = comp_res["loc"]
            cc_score = comp_res["cyclomatic_complexity"]
            mi_score = comp_res["maintainability_index"]
            ml_prob = MLBugPredictor.predict_defect_probability(source_code)
            scores = compute_scores(mi_score, cc_score, all_findings, ml_prob)

        analysis_record = Analysis(
            user_id=user_id,
            filename=filename,
            language="python",
            source_code=source_code,
            loc=loc,
            cyclomatic_complexity=cc_score,
            maintainability_index=mi_score,
            quality_score=scores["quality_score"],
            security_score=scores["security_score"],
            ml_bug_probability=ml_prob,
            status="completed"
        )
        db.session.add(analysis_record)
        db.session.flush()

        for item in all_findings:
            bug_record = Bug(
                analysis_id=analysis_record.id,
                cwe_id=item.get("cwe_id"),
                category=item.get("category", "General"),
                severity=item.get("severity", "Medium"),
                line_number=item.get("line_number"),
                function_name=item.get("function_name"),
                title=item.get("title"),
                description=item.get("description"),
                code_snippet=item.get("code_snippet"),
                recommendation=item.get("recommendation"),
                patch_diff=item.get("patch_diff")
            )
            db.session.add(bug_record)

        db.session.commit()
        return analysis_record
'''
}

for filepath, content in FILES_CONTENT.items():
    p = Path(filepath)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    print(f"Populated: {filepath}")

print("\nAll Step 3 & Step 4 core engine files written successfully!")