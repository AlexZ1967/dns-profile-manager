#!/usr/bin/python3
"""Move owned DNS definitions out of ~/.bash_aliases; install one guarded source."""
import datetime
import json
import re
import shlex
import subprocess
from pathlib import Path
import dns_manager as manager

HOOK_START = '# >>> DNS Profile Manager >>>'
HOOK_END = '# <<< DNS Profile Manager <<<'
LEGACY_START = '# DNS профили:'
LEGACY_HOOK = '# DNS Manager: shared provider configuration and generated CLI commands.'
NETWORK_NAMES = ('DNS_ETH_UUID', 'DNS_WIFI_UUID', 'DNS_INTERFACES', 'DNS_PROFILE_CONF', 'DNS_LEGACY_CONFS')
OWNED_VARIABLES = set(NETWORK_NAMES) | {'DNS_XBOX_SERVERS', 'DNS_AI_SERVERS', 'DNS_DAGAMI_SERVERS', 'DNS_MAGIC_SERVERS', 'DNS_AI_DIR', 'DNS_AI_SCRIPT', 'DNS_AI_URL'}
OWNED_FUNCTIONS = {'_dns_active_connections', '_dns_nm_configure', '_dns_clear_profiles', '_dns_switch', '_dns_provider_apply',
                   'dns-provider', 'xbox-dns-on', 'xbox-dns-off', 'dns-ai-on', 'dns-ai-off', 'dns-ai-update',
                   'dns-dagami-on', 'dns-dagami-off', 'dns-magic-on', 'dns-magic-off', 'dns-status', 'dns-details'}
FUNCTION = re.compile(r'^([a-zA-Z_][a-zA-Z0-9_-]*)\(\)\s*([({])(.*)$')
ASSIGNMENT = re.compile(r'^([A-Z_][A-Z0-9_]*)=(.*)$')


def syntax(text, title):
    result = subprocess.run(['bash', '-n'], input=text, capture_output=True, text=True)
    if result.returncode:
        raise manager.ManagerError(f'Ошибка синтаксиса {title}: {result.stderr.strip()}')


def hook_text():
    entry = shlex.quote(str(manager.ROOT / 'shell/dns.bash'))
    return f'{HOOK_START}\n[[ ! -r {entry} ]] || source {entry}\n{HOOK_END}\n'


def owned_region(original):
    """Use explicit boundaries; never truncate an unrelated suffix."""
    if HOOK_START in original:
        if original.count(HOOK_START) != 1 or original.count(HOOK_END) != 1:
            raise manager.ManagerError('Неоднозначный блок подключения DNS Manager в aliases.')
        start = original.index(HOOK_START)
        end = original.index(HOOK_END, start) + len(HOOK_END)
        if original[end:end+1] == '\n':
            end += 1
        expected = original[start:end]
        # Accept only the known generated hook; avoid replacing extra user commands inside its markers.
        lines = expected.splitlines()
        tokens = shlex.split(lines[1], comments=True) if len(lines) == 3 else []
        valid = len(tokens) == 8 and tokens[:3] == ['[[', '!', '-r'] and tokens[4:7] == [']]', '||', 'source'] and tokens[3] == tokens[7] and Path(tokens[3]).name == 'dns.bash'
        if not valid or LEGACY_START in original:
            raise manager.ManagerError('В блок подключения DNS добавлены другие команды. Автоматическая замена остановлена.')
        return start, end, None
    start = next((m.start() for m in re.finditer(r'(?m)^# DNS профили:.*$', original)), None)
    if start is None:
        raise manager.ManagerError('Исходный DNS-раздел не найден. Общий aliases не изменён.')
    marker = original.find(LEGACY_HOOK, start)
    if marker >= 0:
        line_end = original.find('\n', marker)
        source_start = line_end + 1
        source_end = original.find('\n', source_start)
        if source_end < 0:
            source_end = len(original)
        source_line = original[source_start:source_end]
        tokens = shlex.split(source_line)
        if len(tokens) != 2 or tokens[0] not in ('source', '.') or Path(tokens[1]) != manager.CONFIG.parent/'commands.bash':
            raise manager.ManagerError('Неожиданная строка подключения старых DNS-команд. Aliases не изменён.')
        end = source_end + (source_end < len(original))
    else:
        # Before the first integration the DNS section had no closing marker.
        # It is accepted only when every non-comment node through EOF is an owned DNS declaration.
        end = len(original)
    return start, end, original[start:end]


def declarations(region):
    """Conservatively recognize legacy definitions without executing the shared file."""
    lines = region.splitlines()
    found = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith('#'):
            index += 1
            continue
        assignment = ASSIGNMENT.fullmatch(line)
        function = FUNCTION.fullmatch(line)
        if assignment and assignment[1] in OWNED_VARIABLES:
            name, value = assignment.groups()
            block = [value]
            if value.strip().startswith('(') and not value.rstrip().endswith(')'):
                index += 1
                while index < len(lines) and lines[index].strip() != ')':
                    block.append(lines[index]); index += 1
                if index == len(lines):
                    raise manager.ManagerError(f'Незавершённый массив {name}.')
                block.append(')')
            if name in NETWORK_NAMES:
                raw = '\n'.join(block).strip()
                is_array = raw.startswith('(') and raw.endswith(')')
                tokens = shlex.split(raw[1:-1] if is_array else raw, comments=True)
                if not is_array and len(tokens) != 1:
                    raise manager.ManagerError(f'Нельзя однозначно перенести {name}.')
                found[name] = tokens if is_array else tokens[0]
            index += 1
            continue
        if function and function[1] in OWNED_FUNCTIONS:
            opening, remainder = function[2], function[3].strip()
            closing = '}' if opening == '{' else ')'
            if remainder:
                if not remainder.endswith(closing):
                    raise manager.ManagerError(f'Неизвестный формат функции {function[1]}.')
            else:
                index += 1
                while index < len(lines) and lines[index].strip() != closing:
                    # Function closes must be at column zero, as in the inspected legacy DNS block.
                    index += 1
                if index == len(lines) or lines[index] != closing:
                    raise manager.ManagerError(f'Не удалось выделить функцию {function[1]}.')
            index += 1
            continue
        if line.startswith('source ') or line.startswith('. '):
            tokens = shlex.split(line)
            if len(tokens) == 2 and Path(tokens[1]) == manager.CONFIG.parent/'commands.bash':
                index += 1
                continue
        raise manager.ManagerError('В DNS-разделе есть посторонняя или неизвестная строка; файл не изменён: ' + line[:120])
    return validate_network_settings(found)


def validate_network_settings(settings):
    if set(settings) != set(NETWORK_NAMES):
        raise manager.ManagerError('Для переноса нужны UUID Ethernet/Wi-Fi, интерфейсы и существующие пути resolved.')
    for key in ('DNS_ETH_UUID', 'DNS_WIFI_UUID'):
        if not isinstance(settings[key], str) or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', settings[key]):
            raise manager.ManagerError('Некорректный UUID в ' + key)
    interfaces = settings['DNS_INTERFACES']
    if not isinstance(interfaces,list) or len(interfaces) != 2 or any(not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', item) for item in interfaces):
        raise manager.ManagerError('Нужны два корректных имени интерфейсов: Ethernet и Wi-Fi.')
    if not isinstance(settings['DNS_PROFILE_CONF'],str) or not Path(settings['DNS_PROFILE_CONF']).is_absolute():
        raise manager.ManagerError('Путь управляемого профиля resolved должен быть абсолютным.')
    legacy = settings['DNS_LEGACY_CONFS']
    if not isinstance(legacy,list) or any(not Path(item).is_absolute() for item in legacy):
        raise manager.ManagerError('Некорректные пути прежних конфигураций DNS.')
    return settings


def network_text(settings):
    lines = ['# Local machine settings for DNS Profile Manager. Not part of the Git repository.',
             '# DNS server addresses and provider commands live in providers.json.']
    for key in NETWORK_NAMES:
        value = settings[key]
        literal = '(' + ' '.join(shlex.quote(item) for item in value) + ')' if isinstance(value,list) else shlex.quote(value)
        lines.append(f'{key}={literal}')
    return '\n'.join(lines) + '\n'


def integrate():
    for relative in ('shell/dns.bash', 'shell/network.bash'):
        path = manager.ROOT/relative
        if not path.is_file():
            raise manager.ManagerError('Не найден модуль проекта: ' + str(path))
        syntax(path.read_text(), relative)
    with manager.lock(manager.CACHE/'operation.lock'), manager.lock(manager.CONFIG.parent/'config.lock', blocking=True):
        original = manager.ALIASES.read_text()
        start, end, legacy_region = owned_region(original)
        migrated = declarations(legacy_region) if legacy_region is not None else None
        settings_file = manager.NETWORK_CONFIG
        if settings_file.exists():
            existing = declarations(settings_file.read_text())
            if migrated is not None and existing != migrated:
                raise manager.ManagerError('network.bash уже существует и отличается от настроек aliases. Автоматическая замена остановлена.')
            settings = existing
        elif migrated is not None:
            settings = migrated
        else:
            raise manager.ManagerError('Отсутствует network.bash; восстановите его из резервной копии.')
        local_settings = network_text(settings)
        syntax(local_settings, str(settings_file))
        updated = original[:start] + hook_text() + original[end:]
        syntax(updated, str(manager.ALIASES))
        data = manager.load_config() if manager.CONFIG.exists() else manager.validate_config(json.loads((manager.ROOT/'providers.default.json').read_text()))
        manager.check_command_paths(data)
        changed = updated != original
        backup = None
        if changed:
            stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
            backup = manager.CONFIG.parent/'backups'/('bash_aliases.'+stamp)
            manager.atomic_write(backup, original)
        if not settings_file.exists():
            manager.atomic_write(settings_file, local_settings)
        if not manager.CONFIG.exists():
            manager.atomic_write(manager.CONFIG, json.dumps(data, ensure_ascii=False, indent=2)+'\n')
        manager.install_commands(data)
        if changed:
            manager.atomic_write(manager.ALIASES, updated, manager.ALIASES.stat().st_mode & 0o777)
        print('Подключение DNS:', manager.ROOT/'shell/dns.bash')
        print('Локальные настройки:', settings_file)
        if backup:
            print('Резервная копия aliases:', backup)
        else:
            print('Подключение уже актуально; общий файл aliases не перезаписывался.')
        print('Сеть и системные файлы не изменялись.')


if __name__ == '__main__':
    try:
        integrate()
    except (manager.ManagerError, OSError, ValueError) as exc:
        raise SystemExit('Ошибка: '+str(exc))
