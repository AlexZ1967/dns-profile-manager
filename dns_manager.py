"""Shared provider configuration, runtime status and non-invasive diagnostics."""
import argparse
import concurrent.futures
import contextlib
import copy
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import dns_diagnostics as probes

ROOT = Path(__file__).resolve().parent
__version__ = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
LOCAL = ROOT / '.local'
_default_config = LOCAL / 'config/providers.json'
if not _default_config.exists():
    _default_config = Path.home() / '.config/dns-manager/providers.json'
CONFIG = Path(os.environ.get('DNS_MANAGER_CONFIG', str(_default_config)))
CACHE = Path(os.environ.get('DNS_MANAGER_CACHE', str(LOCAL / 'cache' if CONFIG.parent == LOCAL / 'config' else Path.home() / '.cache/dns-manager')))
ALIASES = Path(os.environ.get('DNS_ALIASES_FILE', str(Path.home() / '.bash_aliases')))
NETWORK_BACKEND = ROOT / 'shell/network.bash'
NETWORK_CONFIG = Path(os.environ.get('DNS_MANAGER_NETWORK_CONFIG', str(CONFIG.parent / ('network.json' if (CONFIG.parent / 'network.json').exists() else 'network.bash'))))
PROFILE_FILE = Path('/etc/systemd/resolved.conf.d/90-alex-dns-profile.conf')
if NETWORK_CONFIG.suffix == '.json' and NETWORK_CONFIG.exists():
    import dns_network
    try:
        PROFILE_FILE = Path(dns_network.load(NETWORK_CONFIG)['profile_file'])
    except (ValueError, OSError, TypeError, KeyError):
        pass  # The backend reports invalid settings before any network mutation.
MODE_NAMES = {'dhcp': 'DHCP', 'dot': 'DNS over TLS', 'plain': 'DNS · UDP/TCP'}
DOMAIN = re.compile(r'(?=.{1,253}\Z)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z')
RESERVED = {'dns-status', 'dns-details', 'dns-check', 'dns-ai-update', 'dns-menu', 'dns-gui', 'dns-manager'}


class ManagerError(Exception):
    pass


def run(args, timeout=12, **kwargs):
    try:
        return subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, '', f'Таймаут ({timeout} с)')
    except OSError as exc:
        return subprocess.CompletedProcess(args, 127, '', str(exc))


def output(args, timeout=12):
    result = run(args, timeout)
    if result.returncode:
        raise ManagerError(result.stderr.strip() or f'Ошибка команды {args[0]}')
    return result.stdout.strip()


def atomic_write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def lock(path, blocking=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a+') as stream:
        os.chmod(path, 0o600)
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            raise ManagerError('Другая операция DNS уже выполняется. Дождитесь её завершения.')
        yield


def validate_config(data):
    if not isinstance(data, dict):
        raise ManagerError('Корень конфигурации должен быть JSON-объектом.')
    if data.get('version') != 1:
        raise ManagerError('Неизвестная версия конфигурации.')
    providers = data.get('providers')
    if not isinstance(providers, list) or not providers or len(providers) > 50:
        raise ManagerError('В конфиге должно быть от 1 до 50 провайдеров.')
    ids, commands, signatures = set(), set(), {}
    for p in providers:
        if not isinstance(p, dict):
            raise ManagerError('Описание провайдера должно быть JSON-объектом.')
        ident = p.get('id', '')
        if not isinstance(ident, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,39}', ident) or ident in ids:
            raise ManagerError('ID: уникальное латинское имя, цифры и дефисы, до 40 символов.')
        ids.add(ident)
        for key in ('name', 'description', 'website', 'tls_hostname', 'command'):
            if not isinstance(p.get(key, ''), str) or any(ord(c) < 32 for c in p.get(key, '')):
                raise ManagerError(f'Недопустимое поле {key} у {ident}.')
        if not p.get('name', '').strip() or len(p['name']) > 80:
            raise ManagerError('Укажите название провайдера (до 80 символов).')
        mode = p.get('mode')
        if not isinstance(mode, str) or mode not in MODE_NAMES or (mode == 'dhcp') != (ident == 'provider'):
            raise ManagerError('DHCP зарезервирован для профиля provider. Другие режимы: dot и plain.')
        servers = p.get('servers')
        if not isinstance(servers, list) or (mode != 'dhcp' and not servers) or len(servers) > 8:
            raise ManagerError('Укажите от 1 до 8 IP-адресов DNS.')
        try:
            for server in servers:
                if not isinstance(server, str):
                    raise ValueError('IP address must be text')
                ipaddress.ip_address(server)
        except (ValueError, TypeError):
            raise ManagerError('Серверы должны быть IPv4/IPv6 адресами без порта и имени хоста.')
        servers = p['servers'] = [str(ipaddress.ip_address(server)) for server in servers]
        p['tls_hostname'] = p.get('tls_hostname', '').lower()
        if len(set(servers)) != len(servers) or (mode == 'dhcp' and servers):
            raise ManagerError('Повторяющиеся серверы или ручные адреса в режиме DHCP.')
        if mode == 'dot' and not DOMAIN.fullmatch(p.get('tls_hostname', '')):
            raise ManagerError('Для DoT укажите TLS-имя, например dns.example.org, без https://.')
        if mode != 'dot' and p.get('tls_hostname'):
            raise ManagerError('TLS-имя используется только в режиме DoT.')
        if type(p.get('port')) is not int or not 1 <= p['port'] <= 65535:
            raise ManagerError('Порт должен быть числом от 1 до 65535.')
        signature = (mode, tuple(sorted(servers)), p.get('tls_hostname', ''), p['port'])
        if signature in signatures:
            raise ManagerError('Такие параметры DNS уже есть у провайдера ' + signatures[signature] + '. Измените существующий профиль.')
        signatures[signature] = p['name']
        if p.get('website') and not re.fullmatch(r'https?://[^\s<>]+', p['website']):
            raise ManagerError('Сайт должен начинаться с https:// или http://.')
        if ident == 'provider' and p['command'] != 'dns-provider':
            raise ManagerError('CLI-команда DHCP-профиля должна оставаться dns-provider.')
        aliases = p.get('off_commands', [])
        if not isinstance(aliases, list):
            raise ManagerError('off_commands должен быть списком.')
        for command in [p['command'], *aliases]:
            if not isinstance(command, str) or not re.fullmatch(r'(?:dns-|xbox-dns-)[a-z0-9-]+', command):
                raise ManagerError('CLI-команда должна начинаться с dns- или xbox-dns- и содержать латинские буквы, цифры и дефисы.')
            if command in commands or command in RESERVED or (command == 'dns-provider' and ident != 'provider'):
                raise ManagerError(f'CLI-команда {command} уже занята или зарезервирована.')
            commands.add(command)
    if 'provider' not in ids:
        raise ManagerError('Необходим профиль provider для возврата к DNS провайдера.')
    services = diagnostic_services(data)
    if not 1 <= len(services) <= 20:
        raise ManagerError('Укажите от 1 до 20 сервисов для диагностики.')
    ids, hosts = set(), set()
    for service in services:
        if not isinstance(service, dict):
            raise ManagerError('Описание проверяемого сервиса должно быть JSON-объектом.')
        ident, host, name = service.get('id', ''), service.get('host', ''), service.get('name', '')
        if not isinstance(ident, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,39}', ident) or ident in ids:
            raise ManagerError('ID проверяемого сервиса должен быть уникальным латинским именем.')
        if not isinstance(host, str) or not DOMAIN.fullmatch(host) or host.lower() in hosts:
            raise ManagerError('Укажите уникальное DNS-имя сервиса без https:// и пути.')
        if not isinstance(name, str) or not name.strip() or len(name) > 80 or any(ord(c)<32 for c in name):
            raise ManagerError('Укажите корректное название проверяемого сервиса.')
        if service.get('role', 'ai') not in ('ai', 'control'):
            raise ManagerError('Роль сервиса: ai или control.')
        ids.add(ident); hosts.add(host.lower())
    if 'test_services' in data:
        for service in data['test_services']:
            service['host'] = service['host'].lower()
            service.setdefault('role', 'ai')
    for key, maximum in [('dns_timeout', 10), ('https_timeout', 20)]:
        if type(data.get(key)) is not int or not 1 <= data[key] <= maximum:
            raise ManagerError(f'Недопустимый таймаут {key}.')
    return data


def diagnostic_services(data):
    if 'test_services' in data:
        if not isinstance(data['test_services'], list):
            raise ManagerError('test_services должен быть списком сервисов.')
        services = copy.deepcopy(data['test_services'])
        for service in services:
            if isinstance(service, dict):
                service.setdefault('role', 'ai')
        return services
    # Read old v1 configurations without changing them automatically.
    domains = data.get('test_domains')
    if not isinstance(domains, list) or any(not isinstance(d, str) or not DOMAIN.fullmatch(d) for d in domains):
        raise ManagerError('Укажите test_services либо список test_domains.')
    known = {s['host']: s for s in probes.DEFAULT_SERVICES}
    return [copy.deepcopy(known.get(domain, {'id': 'service-' + str(i), 'name': domain, 'host': domain, 'role': 'control'})) for i,domain in enumerate(domains)]


def upgraded_diagnostics_config(data):
    updated = copy.deepcopy(data)
    if 'test_services' not in updated:
        existing = diagnostic_services(data)
        updated['test_services'] = copy.deepcopy(probes.DEFAULT_SERVICES)
        hosts = {s['host'] for s in updated['test_services']}
        for service in existing:
            if service['host'] not in hosts:
                updated['test_services'].append(service)
        updated.pop('test_domains', None)
    return validate_config(updated)


def diagnostics_signature(data):
    return fingerprint({'version': probes.PROBE_VERSION, 'services': diagnostic_services(data),
                        'dns_timeout': data['dns_timeout'], 'https_timeout': data['https_timeout']})


def load_config():
    try:
        return validate_config(json.loads(CONFIG.read_text()))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ManagerError(f'Не удалось прочитать конфиг {CONFIG}: {exc}')


def provider(data, ident):
    for item in data['providers']:
        if item['id'] == ident:
            return item
    raise ManagerError(f'Неизвестный провайдер: {ident}')


def command_map(data):
    result = {'dns-status': ('status',), 'dns-details': ('details',), 'dns-check': ('check',)}
    for p in data['providers']:
        result[p['command']] = ('apply', p['id'])
        for command in p.get('off_commands', []):
            result[command] = ('apply', 'provider')
    return result


def check_command_paths(data):
    for name in ['dnsctl', *command_map(data)]:
        path = Path.home() / '.local/bin' / name
        expected = ROOT / ('dnsctl' if name == 'dnsctl' else 'dns-provider-command')
        if os.path.lexists(path) and (not path.is_symlink() or path.resolve() != expected.resolve()):
            raise ManagerError(f'Команда {path} уже существует и не принадлежит DNS Manager.')


def install_commands(data):
    check_command_paths(data)
    lines = ['# Generated DNS Manager command routing. Provider settings live in providers.json.']
    for command, args in command_map(data).items():
        lines.append(f'{command}() {{ {shlex.quote(str(ROOT / "dnsctl"))} ' + ' '.join(shlex.quote(a) for a in args) + ' "$@"; }')
    lines.append('dnsctl() { ' + shlex.quote(str(ROOT / 'dnsctl')) + ' "$@"; }')
    atomic_write(CONFIG.parent / 'commands.bash', '\n'.join(lines) + '\n')
    local_bin = Path.home() / '.local/bin'
    local_bin.mkdir(parents=True, exist_ok=True)
    wanted = {'dnsctl', *command_map(data)}
    for name in wanted:
        path = local_bin / name
        if not os.path.lexists(path):
            path.symlink_to(ROOT / ('dnsctl' if name == 'dnsctl' else 'dns-provider-command'))
    for path in local_bin.iterdir():
        if path.is_symlink() and path.resolve() == (ROOT / 'dns-provider-command').resolve() and path.name not in wanted:
            path.unlink()


def save_config(data, install=True, expected_hash=None):
    validate_config(data)
    with lock(CACHE / 'operation.lock'), lock(CONFIG.parent / 'config.lock', blocking=True):
        if install:
            require_installation()
        if expected_hash and CONFIG.exists() and fingerprint(load_config()) != expected_hash:
            raise ManagerError('Конфиг изменён другим окном. Обновите список и повторите редактирование.')
        if install:
            check_command_paths(data)
        if CONFIG.exists():
            atomic_write(CONFIG.with_suffix('.json.bak'), CONFIG.read_text())
        atomic_write(CONFIG, json.dumps(data, ensure_ascii=False, indent=2) + '\n')
        if install:
            install_commands(data)


def fingerprint(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def server_tokens(p):
    result = []
    for ip in p['servers']:
        port = p['port']
        token = ip
        if port != (853 if p['mode'] == 'dot' else 53):
            token = f'[{ip}]:{port}' if ':' in ip else f'{ip}:{port}'
        if p['mode'] == 'dot':
            token += '#' + p['tls_hostname']
        result.append(token)
    return result


def active_connections():
    # Use the CLI's existing UUID allow-list, never include VPN or inactive profiles.
    script = 'DNS_MANAGER_NETWORK_CONFIG="$2"; source "$1" || exit 1; _dns_active_connections'
    text = output(['bash', '-c', script, '_', str(NETWORK_BACKEND), str(NETWORK_CONFIG)])
    result = []
    for line in text.splitlines():
        if '|' not in line:
            continue
        uuid, iface = line.split('|', 1)
        info = output(['nmcli', '-g', 'connection.id,ipv4.ignore-auto-dns,ipv6.ignore-auto-dns,ipv4.dns,ipv6.dns', 'connection', 'show', uuid]).split('\n')
        info += [''] * (5 - len(info))
        result.append({'uuid': uuid, 'interface': iface, 'name': info[0], 'ignore4': info[1], 'ignore6': info[2], 'dns4': info[3], 'dns6': info[4]})
    return result


def route_info():
    result = run(['ip', '-j', '-4', 'route', 'get', '1.1.1.1'])
    try:
        route = json.loads(result.stdout)[0]
        return {'interface': route.get('dev', ''), 'gateway': route.get('gateway', ''), 'source': route.get('prefsrc', '')}
    except (ValueError, IndexError, TypeError):
        return {'interface': '', 'gateway': '', 'source': ''}


def network_fingerprint(connections=None):
    if connections is None:
        connections = active_connections()
    return fingerprint({'connections': sorted((c['uuid'],c['interface']) for c in connections), 'route': route_info()})


def current_state(data=None):
    data = data or load_config()
    connections = active_connections()
    route = route_info()
    live = output(['resolvectl', 'dns'])
    global_line = next((line.partition(':')[2].strip() for line in live.splitlines() if line.startswith('Global:')), '')
    fields = {}
    if PROFILE_FILE.exists():
        for line in PROFILE_FILE.read_text().splitlines():
            if '=' in line and not line.lstrip().startswith(('#',';')):
                key, value = line.split('=',1)
                fields[key.strip()] = value.strip()
    actual = set(fields.get('DNS', '').split())
    dot = fields.get('DNSOverTLS', 'no') == 'yes'
    match, exact = None, False
    if actual:
        for p in data['providers']:
            if p['mode'] == 'dhcp':
                continue
            if actual == set(server_tokens(p)) and dot == (p['mode'] == 'dot') and fields.get('Domains') == '~.':
                match, exact = p, True
                break
        if match is None:
            for p in data['providers']:
                if p['mode'] == 'dot' and p['tls_hostname'] and all(token.endswith('#' + p['tls_hostname']) for token in actual):
                    match = p
                    break
    elif not global_line and connections and all(c['ignore4'] == 'no' and c['ignore6'] == 'no' and not c['dns4'] and not c['dns6'] for c in connections):
        match, exact = provider(data, 'provider'), True
    effective = actual == set(global_line.split()) if actual else not global_line
    return {'id': match['id'] if match else None, 'name': match['name'] if match else 'Другие / несогласованные настройки',
            'config_matches': exact, 'effective_matches': effective, 'servers': sorted(actual), 'dot': dot,
            'connections': connections, 'route': route, 'network': network_fingerprint(connections),
            'global_dns': global_line, 'config_file': str(CONFIG)}


def machine_identifier():
    return hashlib.sha256(Path('/etc/machine-id').read_bytes().strip()).hexdigest()


def require_installation():
    if CONFIG.parent == LOCAL / 'config':
        record = LOCAL / 'installation.json'
        try:
            data = json.loads(record.read_text())
        except (OSError, ValueError):
            raise ManagerError('Выполните ./install на этом компьютере.')
        if data.get('state') != 'installed' or data.get('machine_id') != machine_identifier():
            raise ManagerError('Установка не активна на этом компьютере. Выполните ./install.')


def apply_profile(ident, emit=print, gui=False):
    data = load_config()
    p = provider(data, ident)
    with lock(CACHE / 'operation.lock'):
        require_installation()
        script = '''DNS_MANAGER_NETWORK_CONFIG="$2"
source "$1" || exit 1
if [[ "${DNS_MANAGER_GUI:-0}" == 1 ]]; then sudo() { /usr/bin/sudo -A "$@"; }; fi
if [[ "$3" == dhcp ]]; then _dns_provider_apply; else _dns_switch "$4" "$5" "$6"; fi'''
        args = ['bash', '-c', script, '_', str(NETWORK_BACKEND), str(NETWORK_CONFIG), p['mode'], p['name'], ' '.join(server_tokens(p)), 'yes' if p['mode'] == 'dot' else 'no']
        emit(f'Применяю {p["name"]}. Только активные известные Ethernet/Wi-Fi; без переподключения.')
        # Inherit the terminal for sudo in CLI; GUI uses askpass and streamed output.
        env = {**os.environ, 'DNS_MANAGER_GUI': '1', 'SUDO_ASKPASS': str(ROOT / 'dns-askpass')} if gui else None
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace', env=env)
        for line in process.stdout:
            emit(line.rstrip('\n'))
        code = process.wait()
        if code:
            raise ManagerError(f'Переключение завершилось с ошибкой {code}. Проверьте фактический статус.')
        state = current_state(data)
        if state['id'] != ident or not state['config_matches'] or not state['effective_matches']:
            raise ManagerError('Команды выполнены, но фактический DNS не совпадает с выбранным профилем. Откройте диагностику.')
        emit(f'Выбран профиль: {p["name"]}. Работоспособность DNS проверяется отдельно.')
        return state


def dhcp_servers():
    servers = []
    for connection in active_connections():
        result = run(['nmcli', '-g', 'DHCP4.OPTION', 'device', 'show', connection['interface']])
        for match in re.finditer(r'(?:^|\n|\|)\s*domain_name_servers\s*=\s*([^|\n]+)', result.stdout):
            for value in match.group(1).split():
                try:
                    ipaddress.ip_address(value)
                    if value not in servers:
                        servers.append(value)
                except ValueError:
                    pass
    return servers


def dns_query(p, server, domain, timeout):
    args = ['kdig', '@' + server, '-p', str(p['port']), domain, 'A', '+json', f'+timeout={timeout}', '+retry=0']
    if p['mode'] == 'dot':
        args += ['+tls-ca', '+tls-hostname=' + p['tls_hostname'], '+tls-sni=' + p['tls_hostname']]
    started = time.monotonic()
    response = run(args, timeout + 2)
    addresses, reason = [], ''
    try:
        body = json.loads(response.stdout)
        if not isinstance(body, dict):
            raise ValueError('Некорректный JSON DNS-ответа')
        if response.returncode == 0 and body.get('RCODE') == 0:
            for rr in body.get('answerRRs', []):
                if rr.get('TYPE') == 1:
                    ip = str(ipaddress.IPv4Address(rr['rdataA']))
                    if ip != '0.0.0.0' and ip not in addresses:
                        addresses.append(ip)
        if body.get('RCODE') != 0:
            reason = f'DNS RCODE={body.get("RCODE")}'
        elif not addresses:
            reason = 'DNS не вернул IPv4-адрес (A)'
    except (ValueError, KeyError, TypeError):
        reason = (response.stderr or response.stdout).strip()[-600:] or 'Нет DNS-ответа'
    if response.returncode:
        reason = (response.stderr or response.stdout).strip()[-600:] or f'Ошибка DNS {response.returncode}'
    return {'server': server, 'domain': domain, 'ok': bool(addresses) and response.returncode == 0,
            'addresses': addresses, 'detail': reason, 'ms': round((time.monotonic()-started)*1000)}


def https_query(domain, address, timeout, path='/'):
    return probes.probe_https(domain, address, timeout, run, path)


def check_provider(ident, emit=None, on_event=None):
    data = load_config()
    p = copy.deepcopy(provider(data, ident))
    services = diagnostic_services(data)
    domains = [s['host'] for s in services]
    start_network = network_fingerprint()
    servers = p['servers'] if p['mode'] != 'dhcp' else dhcp_servers()
    result = {
        'id': ident, 'name': p['name'], 'tested_servers': servers,
        'checked_at': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
        'fingerprint': fingerprint(p), 'network': start_network, 'probe_version': probes.PROBE_VERSION,
        'diagnostics_signature': diagnostics_signature(data), 'state': 'unknown',
        'dns': [], 'https': [], 'issues': [], 'services': [], 'route': route_info(),
        'profile': {'mode': p['mode'], 'tls_hostname': p['tls_hostname'], 'port': p['port']},
    }

    def event(kind, **values):
        if on_event:
            on_event({'kind': kind, 'id': ident, 'name': p['name'], **values})

    event('start', services=services, profile=result['profile'], servers=servers, route=result['route'])
    if not shutil.which('kdig') or not shutil.which('curl'):
        result['issues'] = ['Нужны установленные kdig и curl. Проверка не выполнялась.']
    elif not servers:
        result['state'] = 'red'
        result['issues'] = ['DHCP не сообщил DNS-серверы на активных известных подключениях.']
    else:
        if emit:
            emit(f'{p["name"]}: прямые DNS-запросы ({MODE_NAMES[p["mode"]]}), системный профиль не меняется.')
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(dns_query, p, server, domain, data['dns_timeout']) for server in servers for domain in domains]
            dns_total = len(futures)
            for count, future in enumerate(concurrent.futures.as_completed(futures), 1):
                answer = future.result()
                result['dns'].append(answer)
                service = next(s for s in services if s['host'] == answer['domain'])
                event('service', service=probes.summarize_service(service, result['dns'], [], complete=False),
                      progress=0.5 * count / dns_total, phase='DNS', completed=count, total=dns_total)
            pairs = sorted({(r['domain'], r['addresses'][0]) for r in result['dns'] if r['ok']})
            total_checks = dns_total + len(pairs)
            for service in services:
                if not any(domain == service['host'] for domain, ip in pairs):
                    event('service', service=probes.summarize_service(service, result['dns'], []), progress=dns_total / total_checks, phase='DNS', completed=dns_total, total=dns_total)
            if emit:
                emit(f'{p["name"]}: TCP, TLS, HTTP и перенаправления через адреса выбранного DNS, без прокси.')

            def resolve_redirect(host, remaining):
                if not DOMAIN.fullmatch(host):
                    return []
                # Independent pool avoids waiting on workers occupied by HTTPS requests.
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(servers))) as redirects:
                    queries = [redirects.submit(dns_query, p, server, host, min(data['dns_timeout'], remaining)) for server in servers]
                    return [query.result() for query in queries]

            futures = [pool.submit(probes.follow_https, domain, ip, data['https_timeout'], https_query, resolve_redirect) for domain, ip in pairs]
            for count, future in enumerate(concurrent.futures.as_completed(futures), 1):
                answer = future.result()
                result['https'].append(answer)
                service = next(s for s in services if s['host'] == answer['domain'])
                expected = sum(domain == service['host'] for domain, ip in pairs)
                received = sum(r['domain'] == service['host'] for r in result['https'])
                event('service', service=probes.summarize_service(service, result['dns'], result['https'], complete=received == expected),
                      progress=(dns_total + count) / total_checks, phase='HTTPS', completed=count, total=len(futures))
        good_dns = sum(item['ok'] for item in result['dns'])
        if not good_dns:
            result['state'] = 'red'
        elif good_dns != len(result['dns']) or not result['https'] or not all(item['ok'] for item in result['https']):
            result['state'] = 'yellow'
        else:
            result['state'] = 'green'
        for server in servers:
            failed = [r['domain'] for r in result['dns'] if r['server'] == server and not r['ok']]
            if failed:
                result['issues'].append(f'DNS {server}: нет корректного ответа для ' + ', '.join(failed))
        result['issues'] += [r['domain'] + ': ' + r['detail'] for r in result['https'] if not r['ok']]
    result['dns'].sort(key=lambda r: (r['domain'], r['server']))
    result['https'].sort(key=lambda r: (r['domain'], r['address']))
    result['services'] = [probes.summarize_service(service, result['dns'], result['https']) for service in services]
    if result['state'] == 'unknown':
        for service in result['services']:
            service.update(state='unknown', detail=result['issues'][0], issues=result['issues'])
    if network_fingerprint() != start_network:
        result['state'] = 'yellow' if any(r['ok'] for r in result['dns']) else 'unknown'
        result['issues'].append('Во время проверки изменились интерфейсы или основной маршрут. Повторите проверку.')
        result['network'] = 'changed-during-check'
        for service in result['services']:
            service.update(state='unknown', detail='Сеть изменилась во время проверки; результат устарел.')
    result['summary'] = probes.summary(result)
    cache_health(result)
    event('finished', result=result, progress=1.0)
    return result



def cache_health(result):
    path = CACHE / 'health.json'
    with lock(CACHE / 'health.lock', blocking=True):
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        data[result['id']] = result
        atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2))


def health_results(data=None, network=None):
    data = data or load_config()
    network = network or network_fingerprint()
    try:
        health = json.loads((CACHE / 'health.json').read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(health, dict):
        return {}
    result = {}
    now = datetime.datetime.now().astimezone()
    for p in data['providers']:
        item = health.get(p['id'])
        if not isinstance(item,dict) or item.get('state') not in {'green','yellow','red','unknown'}:
            continue
        try:
            fresh = 0 <= (now-datetime.datetime.fromisoformat(item['checked_at'])).total_seconds() < 900
        except (ValueError, KeyError, TypeError):
            fresh = False
        same_dhcp = p['mode'] != 'dhcp' or item.get('tested_servers') == dhcp_servers()
        if item.get('fingerprint') == fingerprint(p) and item.get('network') == network and fresh and same_dhcp and item.get('diagnostics_signature') == diagnostics_signature(data):
            result[p['id']] = item
    return result


def format_health(result):
    states = {'green': '✓ Работает', 'yellow': '⚠ Частично работает', 'red': '✕ Не работает', 'unknown': '— Не проверен'}
    def ms(value):
        return f'{value:g} мс' if isinstance(value, (int, float)) else '—'
    lines = [f'{result["name"]}: {states[result["state"]]}', 'Проверено: ' + result['checked_at'], 'Системный DNS не переключался.']
    route = result.get('route', {})
    lines.append(f'Маршрут IPv4: {route.get("interface", "—")} через {route.get("gateway", "—")}')
    summary = result.get('summary', {})
    if summary:
        lines.append(f'ИИ-сервисы: {summary["ai_ok"]}/{summary["ai_total"]}; DNS-серверы: {summary["dns_servers_ok"]}/{summary["dns_servers_total"]}')
        lines.append(f'Медиана DNS: {ms(summary.get("dns_ms"))}; TCP: {ms(summary.get("tcp_ms"))}; HTTPS: {ms(summary.get("https_ms"))}')
    for service in result.get('services', []):
        lines.append(f'\n{service["name"]} ({service["host"]}): {states[service["state"]]}')
        lines.append(f'  DNS {service["dns_ok"]}/{service["dns_total"]} · {ms(service.get("dns_ms"))}; TCP {ms(service.get("tcp_ms"))}; TLS {ms(service.get("tls_ms"))}; HTTPS {ms(service.get("https_ms"))}')
        lines += ['  ' + issue for issue in service['issues']]
    lines.append('\nПодробности запросов:')
    for r in result['dns']:
        lines.append(f'  DNS {r["server"]} → {r["domain"]}: ' + (', '.join(r['addresses']) if r['ok'] else r['detail']) + f' ({r["ms"]} мс)')
    for r in result['https']:
        lines.append(f'  HTTPS {r["domain"]} → {r["address"]}: {r["detail"]}')
        for hop in r.get('hops', []):
            lines.append(f'    {hop.get("url", "")} → {hop.get("address", "")} · {hop["detail"]}')
            timing = hop.get('timings', {})
            lines.append(f'      TCP {ms(timing.get("tcp_ms"))}; TLS {ms(timing.get("tls_ms"))}; первый байт {ms(timing.get("ttfb_ms"))}; всего {ms(timing.get("total_ms"))}')
        for query in r.get('redirect_dns', []):
            lines.append(f'    DNS перехода {query["server"]} → {query["domain"]}: ' + (', '.join(query['addresses']) if query['ok'] else query['detail']))
    lines += ['  ' + text for text in result['issues']]
    return '\n'.join(lines) + '\n'


def diagnostic(details=False, emit=print):
    state = current_state()
    emit(f'Профиль DNS: {state["name"]}')
    emit(f'Основной маршрут: {state["route"]["interface"]} через {state["route"]["gateway"]}')
    commands = [(['ip','-4','route','show','default'], 'Маршруты'),
                (['nmcli','-f','NAME,UUID,TYPE,DEVICE','connection','show','--active'], 'Активные подключения'),
                (['resolvectl','status'], 'systemd-resolved')]
    if details:
        commands += [(['nmcli','device','show'], 'Устройства NetworkManager'),
                     (['systemd-analyze','cat-config','systemd/resolved.conf'], 'Эффективная конфигурация resolved')]
    for args, title in commands:
        emit('\n=== ' + title + ' ===')
        r = run(args)
        emit(r.stdout.strip() or r.stderr.strip())
    emit('\nПрокси-переменные: ' + ('обнаружены' if any(os.environ.get(k) for k in ['http_proxy','https_proxy','all_proxy','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY']) else 'отсутствуют'))
    if not details:
        data = load_config()
        for domain in [service['host'] for service in diagnostic_services(data)]:
            r = run(['resolvectl','query',domain], data['dns_timeout'] + 1)
            emit(f'DNS {domain}: ' + ('OK' if r.returncode == 0 else 'ОШИБКА / TIMEOUT'))
            r = run(['curl','-4','--noproxy','*','--connect-timeout','4','--max-time',str(data['https_timeout']),'-sS','-o','/dev/null','-w','%{http_code}',f'https://{domain}'], data['https_timeout']+2)
            emit(f'HTTPS {domain}: ' + (f'HTTP {r.stdout}' + (' (доступ ограничен)' if r.stdout == '403' else '') if r.returncode == 0 else f'curl {r.returncode}: {r.stderr.strip()}'))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Общий DNS Manager: CLI, GUI и проверки без переключения')
    parser.add_argument('--version', action='version', version='DNS Profile Manager ' + __version__)
    sub = parser.add_subparsers(dest='op', required=True)
    for op in ['list','current']:
        sub.add_parser(op).add_argument('--json', action='store_true')
    sub.add_parser('apply').add_argument('id')
    sub.add_parser('status')
    sub.add_parser('details')
    check = sub.add_parser('check'); check.add_argument('id', nargs='?'); check.add_argument('--all', action='store_true'); check.add_argument('--json', action='store_true')
    command = sub.add_parser('command'); command.add_argument('name'); command.add_argument('args', nargs=argparse.REMAINDER)
    config = sub.add_parser('config'); config.add_argument('operation', choices=['path','show','import','sync-commands','upgrade-checks']); config.add_argument('file', nargs='?')
    args = parser.parse_args(argv)
    try:
        data = load_config()
        if args.op == 'command':
            mapped = command_map(data).get(args.name)
            if mapped is None:
                raise ManagerError('Команда удалена или переименована в конфиге.')
            return main([*mapped,*args.args])
        if args.op == 'list':
            if args.json:
                print(json.dumps(data,ensure_ascii=False))
            else:
                for p in data['providers']:
                    print(f'{p["id"]:12} {p["name"]:22} {MODE_NAMES[p["mode"]]:14} {p["command"]}')
        elif args.op == 'current':
            state = current_state(data)
            print(json.dumps(state,ensure_ascii=False) if args.json else f'{state["name"]}\nМаршрут: {state["route"]["interface"]} через {state["route"]["gateway"]}')
        elif args.op == 'apply':
            apply_profile(args.id)
        elif args.op in ['status','details']:
            diagnostic(args.op == 'details')
        elif args.op == 'check':
            if not args.all and not args.id:
                parser.error('Укажите ID провайдера или --all.')
            items = data['providers'] if args.all else [provider(data,args.id)]
            results = [check_provider(p['id'], None if args.json else print) for p in items]
            if args.json:
                print(json.dumps(results,ensure_ascii=False))
            else:
                for result in results:
                    print(format_health(result))
            return 0 if all(r['state'] == 'green' for r in results) else 1
        elif args.op == 'config':
            if args.operation == 'path': print(CONFIG)
            elif args.operation == 'show': print(json.dumps(data, ensure_ascii=False, indent=2))
            elif args.operation == 'sync-commands': install_commands(data)
            elif args.operation == 'upgrade-checks':
                save_config(upgraded_diagnostics_config(data))
                print('Список проверяемых сервисов обновлён. Системный DNS не изменён.')
            elif args.operation == 'import':
                if not args.file: raise ManagerError('Укажите JSON-файл для импорта.')
                save_config(json.loads(Path(args.file).read_text()))
                print('Конфиг сохранён. Системный DNS не изменён.')
        return 0
    except (ManagerError,OSError,ValueError) as exc:
        print('Ошибка: ' + str(exc),file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
