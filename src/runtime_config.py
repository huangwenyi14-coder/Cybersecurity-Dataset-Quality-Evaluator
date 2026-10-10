"""Literal .env settings; process environment overrides file values.

No shell expansion, command evaluation, or credential logging.
"""
from pathlib import Path
import os, re
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / '.env'
LEGACY_NAMES = {'DEEPSEEK_API_KEY', 'DEEPSEEK_BASE_URL', 'DEEPSEEK_MODEL', 'DEEPSEEK_TIMEOUT_SECONDS'}
AI_NAMES = {'AI_API_KEY', 'AI_BASE_URL', 'AI_MODEL', 'AI_TIMEOUT_SECONDS',
            'AI_JSON_MODE', 'AI_TEMPERATURE', 'AI_TOKEN_PARAMETER', 'AI_THINKING'}
NAMES = LEGACY_NAMES | AI_NAMES


def configure(path=None):
    global ENV_FILE
    ENV_FILE = Path(path).expanduser().resolve() if path else ROOT / '.env'
    if path and not ENV_FILE.is_file():
        raise ValueError('Specified environment file does not exist')


def read_env(path):
    values = {}
    if not Path(path).exists():
        return values
    for number, raw in enumerate(Path(path).read_text(encoding='utf-8-sig').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].lstrip()
        if '=' not in line:
            raise ValueError('Invalid .env assignment at line ' + str(number))
        name, value = line.split('=', 1)
        name = name.strip(); value = value.strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
            raise ValueError('Invalid .env variable name at line ' + str(number))
        if value[:1] in ('"', "'"):
            quote = value[0]
            closing = value.find(quote, 1)
            if closing < 0 or (value[closing+1:].strip() and not value[closing+1:].strip().startswith('#')):
                raise ValueError('Invalid .env quoting at line ' + str(number))
            value = value[1:closing]
        else:
            value = re.split(r'\s+#', value, maxsplit=1)[0].rstrip()
        if name in NAMES:
            values[name] = value
    return values


def settings(require_key=False):
    values = read_env(ENV_FILE)
    values.update({k: os.environ[k] for k in NAMES if k in os.environ})
    # Any generic setting selects a separate profile: never forward a legacy key
    # to a newly configured host by falling back one variable at a time.
    generic = any(k in values for k in AI_NAMES)
    prefix = 'AI_' if generic else 'DEEPSEEK_'
    key = values.get(prefix+'API_KEY', '').strip()
    base = values.get(prefix+'BASE_URL', '' if generic else 'https://api.deepseek.com').strip().rstrip('/')
    try:
        url = urlparse(base)
        port = url.port
        local = url.hostname in ('localhost', '127.0.0.1', '::1')
        valid = bool(url.hostname) and (url.scheme == 'https' or (url.scheme == 'http' and local))
        valid = valid and not (url.username or url.password or url.query or url.fragment)
        valid = valid and not any(c.isspace() or ord(c) < 32 for c in base) and '\\' not in base
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(prefix+'BASE_URL must be an HTTPS API root (HTTP allowed only on loopback), without credentials, query or fragment')
    if not generic and (url.hostname != 'api.deepseek.com' or port not in (None,443) or url.path not in ('','/v1')):
        raise ValueError('Legacy DEEPSEEK_BASE_URL only supports api.deepseek.com; use the AI_* configuration for other services')
    model = values.get(prefix+'MODEL', '' if generic else 'deepseek-flash').strip()
    if not model:
        raise ValueError(prefix+'MODEL is empty')
    try:
        timeout = int(values.get(prefix+'TIMEOUT_SECONDS', '180'))
    except ValueError:
        raise ValueError(prefix+'TIMEOUT_SECONDS must be an integer') from None
    if not 1 <= timeout <= 600:
        raise ValueError(prefix+'TIMEOUT_SECONDS must be between 1 and 600')
    if require_key and not key and not local:
        raise ValueError('Set '+prefix+'API_KEY in .env or use --offline')
    json_mode = values.get('AI_JSON_MODE', 'true').lower()
    if json_mode not in ('true', 'false'):
        raise ValueError('AI_JSON_MODE must be true or false')
    temperature = values.get('AI_TEMPERATURE', 'omit' if generic else '0').strip()
    if temperature != 'omit':
        try:
            temperature = float(temperature)
            if not 0 <= temperature <= 2:
                raise ValueError()
        except ValueError:
            raise ValueError('AI_TEMPERATURE must be omit or a number between 0 and 2') from None
    token_parameter = values.get('AI_TOKEN_PARAMETER', 'max_tokens')
    if token_parameter not in ('max_tokens', 'max_completion_tokens'):
        raise ValueError('AI_TOKEN_PARAMETER must be max_tokens or max_completion_tokens')
    thinking = values.get('AI_THINKING', 'omit' if generic else 'disabled')
    if thinking not in ('omit', 'disabled', 'enabled'):
        raise ValueError('AI_THINKING must be omit, disabled or enabled')
    if '\r' in key or '\n' in key:
        raise ValueError(prefix+'API_KEY contains an invalid newline')
    return {'api_key': key, 'base_url': base, 'model': model, 'timeout': timeout,
            'json_mode': json_mode == 'true', 'temperature': temperature,
            'token_parameter': token_parameter, 'thinking': thinking}
