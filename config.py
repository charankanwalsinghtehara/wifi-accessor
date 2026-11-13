from __future__ import annotations

import os
from typing import List

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()

APP_NAME = 'CyberSentinel AI'
APP_ENV = os.getenv('APP_ENV', 'development')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
DEMO_MODE = os.getenv('DEMO_MODE', 'true').lower() == 'true'
ALLOWED_DOMAINS = [entry.strip() for entry in os.getenv('ALLOWED_DOMAINS', 'example.com,lab.local,internal.local').split(',') if entry.strip()]
ALLOWED_CIDRS = [entry.strip() for entry in os.getenv('ALLOWED_CIDRS', '10.0.0.0/24,192.168.0.0/24,172.16.0.0/16').split(',') if entry.strip()]
LLM_PROVIDER = os.getenv('LLM_PROVIDER', 'none').strip().lower()
LLM_MODEL = os.getenv('LLM_MODEL', '').strip()
OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://127.0.0.1:11434').rstrip('/')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')

class AppConfig(BaseModel):
    app_name: str = Field(default=APP_NAME)
    app_env: str = Field(default=APP_ENV)
    log_level: str = Field(default=LOG_LEVEL)
    demo_mode: bool = Field(default=DEMO_MODE)
    allowed_domains: List[str] = Field(default_factory=lambda: ALLOWED_DOMAINS)
    allowed_cidrs: List[str] = Field(default_factory=lambda: ALLOWED_CIDRS)
    llm_provider: str = Field(default=LLM_PROVIDER)
    llm_model: str = Field(default=LLM_MODEL)

APP_SETTINGS = AppConfig()
