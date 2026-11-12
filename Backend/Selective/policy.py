"""Explicit supported DNS scope for the private selective TUN application."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sites import validate


def validate_selective(cfg, gateway=None):
    validate(cfg)
    if any(row['scope'] != 'tree' for row in cfg['sites']):
        raise ValueError('Эта проба поддерживает только «Имя и все поддомены». Точные правила не расширяются автоматически.')
    def captured(name):
        return any(name == r['domain'] or name.endswith('.' + r['domain']) for r in cfg['sites'])
    if any(captured(name) for name in cfg['beforeLogin']):
        raise ValueError('Исключение для входа находится внутри рабочего DNS-домена. Такой список пока не поддерживается.')
    if gateway and captured(gateway):
        raise ValueError('Шлюз VPN должен находиться вне рабочих DNS-доменов.')
    return cfg
