import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Get DATABASE_URL from .env
DATABASE_URL = os.getenv("DATABASE_URL")

# Create engine
engine = create_engine(DATABASE_URL)

try:
    with engine.connect() as connection:
        result = connection.execute(text("SELECT NOW();"))
        print("✅ Database Connected Successfully!")
        print("Current Time from DB:", result.fetchone())
except Exception as e:
    print("❌ Database Connection Failed")
    print(e)