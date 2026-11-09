import os
from dotenv import load_dotenv
from app import create_app

load_dotenv()

env = os.getenv("FLASK_ENV", "development")
app = create_app(env)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
