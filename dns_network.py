"""Typed machine configuration for fresh installations; Bash is generated from data."""
import argparse
import json
from pathlib import Path
import re
import shlex
import uuid

TYPES = {'802-3-ethernet', '802-11-wireless'}
PROFILE_PATHS = {'/etc/systemd/resolved.conf.d/90-dns-profile-manager.conf', '/etc/systemd/resolved.conf.d/90-alex-dns-profile.conf'}
LOCK = '/run/lock/nm-dns-primary-route.lock'
STATE = '/run/nm-dns-primary-route.state'


def validate(data):
    if not isinstance(data, dict) or data.get('version') != 1:
        raise ValueError('Неизвестный формат network.json.')
    connections = data.get('connections')
    if not isinstance(connections, list) or not 1 <= len(connections) <= 100:
        raise ValueError('Нужно от 1 до 100 физических подключений NetworkManager.')
    seen = set()
    for item in connections:
        if not isinstance(item, dict):
            raise ValueError('Некорректное подключение.')
        ident = item.get('uuid')
        if not isinstance(ident, str) or str(uuid.UUID(ident)) != ident.lower() or ident.lower() in seen:
            raise ValueError('UUID подключений должны быть корректными и уникальными.')
        if item.get('type') not in TYPES:
            raise ValueError('Разрешены только Ethernet и Wi-Fi; VPN не поддерживаются.')
        interface = item.get('interface', '')
        if not isinstance(interface, str) or interface and not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', interface):
            raise ValueError('Некорректное имя интерфейса.')
        item['uuid'] = ident.lower()
        seen.add(ident.lower())
    if data.get('profile_file') not in PROFILE_PATHS:
        raise ValueError('Недопустимый путь управляемого профиля resolved.')
    if data.get('lock_file', LOCK) != LOCK or data.get('state_file', STATE) != STATE:
        raise ValueError('Недопустимые системные пути блокировки / состояния.')
    if data.get('installation_id'):
        uuid.UUID(data['installation_id'])
    return data


def load(path):
    return validate(json.loads(Path(path).read_text()))


def shell(data):
    validate(data)
    specs = [item['uuid']+'|'+item.get('interface','')+'|'+item['type'] for item in data['connections']]
    lines = ['DNS_CONNECTIONS=('+' '.join(shlex.quote(s) for s in specs)+')',
             'DNS_PROFILE_CONF='+shlex.quote(data['profile_file']), 'DNS_LEGACY_CONFS=()',
             'DNS_INSTALLATION_ID='+shlex.quote(data.get('installation_id',''))]
    return '\n'.join(lines)+'\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['shell'])
    parser.add_argument('file')
    args = parser.parse_args()
    try:
        print(shell(load(args.file)), end='')
    except (ValueError, OSError, TypeError) as exc:
        raise SystemExit(str(exc))
