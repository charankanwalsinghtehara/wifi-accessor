from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from typing import Any

from config import LLM_MODEL, LLM_PROVIDER, OLLAMA_BASE_URL, OPENAI_API_KEY


class LLMUnavailableError(RuntimeError):
    """Optional model inference could not be completed."""


def assessment_commentary(findings: list[dict[str, Any]]) -> str | None:
    """Request optional, non-authoritative commentary using sanitized metadata only."""
    provider = LLM_PROVIDER
    if provider in {'', 'none'}:
        return None
    if provider not in {'ollama', 'openai'}:
        raise LLMUnavailableError('LLM_PROVIDER must be none, ollama, or openai.')
    if not LLM_MODEL:
        raise LLMUnavailableError('Set LLM_MODEL to use configured model inference.')

    evidence = [
        {'severity': str(item.get('severity', '')), 'title': str(item.get('title', ''))[:120]}
        for item in findings[:30]
    ]
    prompt = (
        'In at most three sentences, summarize these defensive Wi-Fi configuration findings. '
        'Do not invent observations or recommend attacks. The supplied data contains no credentials. '
        f'Findings: {json.dumps(evidence, ensure_ascii=True)}'
    )
    try:
        if provider == 'ollama':
            return _ollama(prompt)
        return _openai(prompt)
    except (HTTPError, URLError, TimeoutError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise LLMUnavailableError(f'{provider} inference is unavailable.') from exc


def _ollama(prompt: str) -> str:
    parsed = urlparse(OLLAMA_BASE_URL)
    if parsed.scheme != 'http' or parsed.hostname not in {'localhost', '127.0.0.1', '::1'}:
        raise LLMUnavailableError('Ollama must be configured on the local machine.')
    payload = json.dumps({
        'model': LLM_MODEL,
        'messages': [{'role': 'user', 'content': prompt}],
        'stream': False,
    }).encode('utf-8')
    request = Request(f'{OLLAMA_BASE_URL}/api/chat', data=payload, headers={'Content-Type': 'application/json'})
    with urlopen(request, timeout=30) as response:
        content = json.loads(response.read().decode('utf-8'))
    return str(content['message']['content']).strip()


def _openai(prompt: str) -> str:
    if not OPENAI_API_KEY:
        raise LLMUnavailableError('OPENAI_API_KEY is required for OpenAI inference.')
    payload = json.dumps({
        'model': LLM_MODEL,
        'messages': [{'role': 'user', 'content': prompt}],
        'temperature': 0,
    }).encode('utf-8')
    request = Request(
        'https://api.openai.com/v1/chat/completions',
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {OPENAI_API_KEY}',
        },
    )
    with urlopen(request, timeout=30) as response:
        content = json.loads(response.read().decode('utf-8'))
    return str(content['choices'][0]['message']['content']).strip()
