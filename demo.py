import os
import sqlite3
import subprocess
import pickle
import yaml

# 1. CWE-798: Hardcoded Credentials / API Token
ADMIN_API_KEY = "sk_live_998877665544332211"
DATABASE_PASSWORD = "SuperSecretPassword123!"

def process_user_data(user_id, user_command, raw_payload, yaml_stream):
    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()

    # 2. CWE-89: SQL Injection via f-string interpolation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    # 3. CWE-78: OS Command Injection via os.system and shell=True
    os.system("ping -c 1 " + user_command)
    subprocess.Popen(user_command, shell=True)

    # 4. CWE-95: Arbitrary Code Execution via eval()
    evaluated_result = eval(user_command)

    # 5. CWE-502: Insecure Deserialization via pickle and unsafe yaml.load
    deserialized_obj = pickle.loads(raw_payload)
    config_data = yaml.load(yaml_stream)

    # 6. CWE-396 / Logic Flaw: Bare except clause masking errors
    try:
        conn.commit()
    except:
        pass

    return evaluated_result

# 7. CWE-1121 / Complexity: High Cyclomatic Complexity Function
def complex_scoring_engine(score, tier, is_active, is_verified, is_admin):
    if is_admin:
        if tier == "gold":
            if score > 90:
                if is_active:
                    return "Elite Admin Gold"
                else:
                    return "Inactive Admin Gold"
            else:
                return "Standard Admin Gold"
        else:
            if score > 50:
                if is_verified:
                    return "Verified Admin Silver"
                else:
                    return "Unverified Admin Silver"
            else:
                return "Low Admin Silver"
    else:
        if tier == "gold":
            if score > 80:
                return "Elite User"
            else:
                return "Regular User"
        else:
            return "Basic User"

# 8. Syntax Error test (Uncomment this line to test the Syntax Checker)
# print("Missing closing quote