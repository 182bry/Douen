from pathlib import Path
import os
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')


class Config:
    APP_NAME = 'app_main'
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    LLM_BASE_URL = os.getenv('LLM_BASE_URL', 'https://synapse.sergiomathurin.com/v1')
    LLM_API_KEY = os.getenv('LLM_API_KEY', '')
    LLM_MODEL = os.getenv('LLM_MODEL', 'llama3.3-70b-instruct')
    FLASK_HOST = os.getenv('FLASK_HOST', '127.0.0.1')
    FLASK_PORT = int(os.getenv('FLASK_PORT', '5000'))
    POLL_SECONDS = float(os.getenv('POLL_SECONDS', '3'))
    MAX_FEED_ITEMS = int(os.getenv('MAX_FEED_ITEMS', '250'))
    MAX_ALERTS = int(os.getenv('MAX_ALERTS', '150'))
    MAX_NOT_BENIGN = int(os.getenv('MAX_NOT_BENIGN', '150'))
    MODEL_DIR = BASE_DIR / 'trained_models'
    FALLBACK_MODEL_DIR = BASE_DIR / ''
    SIMULATOR_DEFAULT_TARGET = os.getenv('SIMULATOR_DEFAULT_TARGET', 'http://127.0.0.1:5000/api/ingest')
