import os
from dotenv import load_dotenv


load_dotenv()


GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not set")


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./scam_guard.db"
)


ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5173"
).split(",")