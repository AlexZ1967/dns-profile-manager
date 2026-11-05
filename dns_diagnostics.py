"""Measured HTTPS stages and service summaries, independent of system DNS settings."""
import ipaddress
import json
from pathlib import Path
import re
import statistics
import tempfile
import time
from urllib.parse import urljoin, urlsplit

PROBE_VERSION = 2
DEFAULT_SERVICES = [
    {'id': 'claude', 'name': 'Claude', 'host': 'claude.ai', 'role': 'ai'},
    {'id': 'gemini', 'name': 'Gemini', 'host': 'gemini.google.com', 'role': 'ai'},
    {'id': 'chatgpt', 'name': 'ChatGPT', 'host': 'chatgpt.com', 'role': 'ai'},
    {'id': 'perplexity', 'name': 'Perplexity', 'host': 'www.perplexity.ai', 'role': 'ai'},
    {'id': 'aistudio', 'name': 'Google AI Studio', 'host': 'aistudio.google.com', 'role': 'ai'},
    {'id': 'antigravity', 'name': 'Antigravity', 'host': 'antigravity.google', 'role': 'ai'},
    {'id': 'github', 'name': 'GitHub', 'host': 'github.com', 'role': 'control'},
]


def median(values):
    values = [v for v in values if isinstance(v, (int, float)) and v >= 0]
    return round(statistics.median(values), 1) if values else None


def parse_headers(text):
    """Keep the final HTTP header block (excluding cookies and other credentials)."""
    headers = {}
    for line in text.splitlines():
        if line.startswith('HTTP/'):
            headers = {}
        elif ':' in line:
            key, value = line.split(':', 1)
            if key.lower() in {'location', 'content-type', 'server', 'cf-mitigated'}:
                headers[key.lower()] = value.strip()
    return headers


def numeric(data, name):
    try:
        value = float(data.get(name, 0))
        return max(0.0, value) if value == value and value != float('inf') else 0.0
    except (TypeError, ValueError):
        return 0.0


def probe_https(domain, address, timeout, run, path='/'):
    """One HTTPS hop; no curl config, proxy, cookies or implicit redirect DNS."""
    address = str(ipaddress.IPv4Address(address))
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='dns-https-') as directory:
        header_file, body_file = Path(directory) / 'headers', Path(directory) / 'body'
        args = ['curl', '--disable', '-4', '--noproxy', '*', '--proxy', '',
                '--proto', '=https', '--resolve', f'{domain}:443:{address}',
                '--connect-timeout', str(min(4, timeout)), '--max-time', str(timeout),
                '--max-filesize', '262144', '--max-redirs', '0', '-sS',
                '--user-agent', 'DNS-Profile-Manager/1.1 (connection diagnostics)',
                '--dump-header', str(header_file), '--output', str(body_file),
                '--write-out', '%{json}', f'https://{domain}{path}']
        response = run(args, timeout + 2)
        try:
            payload = json.loads(response.stdout)
            if not isinstance(payload, dict):
                payload = {}
        except (ValueError, TypeError):
            payload = {}
        headers = parse_headers(header_file.read_text(errors='replace')) if header_file.exists() else {}
        body = ''
        if body_file.exists():
            with body_file.open('rb') as stream:
                body = stream.read(65536).decode('utf-8', errors='replace').lower()
    try:
        code = int(payload.get('response_code', payload.get('http_code', 0)))
    except (ValueError, TypeError):
        code = 0
    connected, appconnected = numeric(payload, 'time_connect'), numeric(payload, 'time_appconnect')
    tcp_ok = connected > 0
    tls_ok = appconnected > 0 and numeric(payload, 'ssl_verify_result') == 0 and response.returncode not in {35, 51, 58, 60, 77, 83, 90, 91}
    truncated = response.returncode == 63
    transport_ok = response.returncode in {0, 63} and tcp_ok and tls_ok and code > 0
    challenge = headers.get('cf-mitigated', '').lower() == 'challenge'
    title = re.search(r'<title[^>]*>(.*?)</title>', body, re.S)
    restricted_text = title.group(1) if title else (body if 'json' in headers.get('content-type', '') and len(body) < 8192 else '')
    regional = any(s in restricted_text for s in ('not available in your country', 'unsupported_country', 'unavailable in your region', 'country is not supported'))
    if not transport_ok:
        stage = 'TCP' if not tcp_ok else ('TLS' if not tls_ok else 'HTTP')
        detail = f'{stage}: curl {response.returncode}; {response.stderr.strip()[-300:] or "нет корректного ответа"}'
    elif challenge:
        detail = f'HTTP {code}: Cloudflare запросил проверку браузера / CAPTCHA'
    elif regional:
        detail = f'HTTP {code}: в ответе обнаружено сообщение о региональном ограничении'
    elif code == 403:
        detail = 'HTTP 403: сервер ответил, доступ ограничен'
    elif code == 429:
        detail = 'HTTP 429: ограничение частоты запросов'
    elif 300 <= code < 400:
        detail = f'HTTP {code}: перенаправление'
    else:
        detail = f'HTTP {code}'
    if truncated and transport_ok:
        detail += ' · тело страницы ограничено 256 КиБ'
    return {
        'domain': domain, 'address': address, 'url': f'https://{domain}{path}',
        'ok': transport_ok and 200 <= code < 300 and not challenge and not regional,
        'code': code, 'detail': detail, 'curl_code': response.returncode,
        'tcp_ok': tcp_ok, 'tls_ok': tls_ok, 'transport_ok': transport_ok,
        'challenge': challenge, 'regional_restriction': regional,
        'location': headers.get('location', ''), 'body_truncated': truncated,
        'http_version': str(payload.get('http_version', '')),
        'remote_ip': str(payload.get('remote_ip', '')),
        'timings': {
            'tcp_ms': round(connected * 1000, 1) if tcp_ok else None,
            'tls_ms': round(max(0, appconnected - connected) * 1000, 1) if tls_ok else None,
            'ttfb_ms': round(numeric(payload, 'time_starttransfer') * 1000, 1) if code else None,
            'total_ms': round((time.monotonic() - started) * 1000, 1),
        },
    }


def follow_https(domain, address, timeout, probe, resolve):
    """Follow up to five HTTPS redirects, resolving every new host with the same DNS provider."""
    start = time.monotonic()
    deadline = start + timeout
    url = f'https://{domain}/'
    visited, hops, redirect_dns = set(), [], []
    pinned = {domain: address}
    failure = None
    for _ in range(6):
        if url in visited:
            failure = 'Обнаружен цикл HTTP-перенаправлений'
            break
        visited.add(url)
        parsed = urlsplit(url)
        try:
            valid = parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password and parsed.port in (None, 443)
        except ValueError:
            valid = False
        if not valid:
            failure = 'Переход на HTTP, нестандартный порт или URL с учётными данными не выполняется'
            break
        host = parsed.hostname.lower()
        # The resolver validates DNS names; literal addresses in redirects are not a DNS profile test.
        try:
            ipaddress.ip_address(host)
            failure = 'Перенаправление на IP вместо имени сервиса не выполняется'
            break
        except ValueError:
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            failure = 'Истёк общий таймаут HTTPS и перенаправлений'
            break
        if host not in pinned:
            answers = resolve(host, remaining)
            redirect_dns.extend(answers)
            usable = next((a for a in answers if a.get('ok') and a.get('addresses')), None)
            if usable is None:
                failure = f'DNS перенаправления {host}: провайдер не вернул IPv4-адрес'
                break
            pinned[host] = usable['addresses'][0]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            failure = 'Истёк общий таймаут HTTPS и перенаправлений'
            break
        path = (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
        hop = probe(host, pinned[host], remaining) if path == '/' else probe(host, pinned[host], remaining, path=path)
        hops.append(hop)
        if not (300 <= hop['code'] < 400):
            break
        if not hop.get('location'):
            failure = f'HTTP {hop["code"]}: нет адреса перенаправления'
            break
        if not hop.get('transport_ok', True):
            break
        url = urljoin(url, hop['location'])
    else:
        failure = 'Превышен лимит: 5 HTTP-перенаправлений'
    last = dict(hops[-1]) if hops else {'ok': False, 'code': 0, 'detail': 'HTTPS не выполнен', 'tcp_ok': False, 'tls_ok': False}
    first = hops[0] if hops else {}
    timings = {}
    for key in ('tcp_ms', 'tls_ms'):
        values = [h.get('timings', {}).get(key) for h in hops]
        values = [v for v in values if v is not None]
        timings[key] = round(sum(values), 1) if values else None
    timings['ttfb_ms'] = first.get('timings', {}).get('ttfb_ms')
    timings['total_ms'] = round((time.monotonic() - start) * 1000, 1)
    last.update(domain=domain, address=address, hops=hops, redirect_dns=redirect_dns,
                redirects=max(0, len(hops)-1), final_url=last.get('url', url), timings=timings)
    if failure:
        last.update(ok=False, detail=failure)
    elif last.get('ok') and len(hops)>1:
        last['detail'] += f' · переходов: {len(hops)-1}'
    if any(not r.get('ok') for r in redirect_dns) and last.get('ok'):
        last.update(ok=False, detail=last['detail']+' · часть DNS-серверов не ответила для перенаправления')
    return last


def summarize_service(service, dns, https, complete=True):
    answers = [r for r in dns if r['domain'] == service['host']]
    requests = [r for r in https if r['domain'] == service['host']]
    good_dns = [r for r in answers if r['ok']]
    good_http = [r for r in requests if r['ok']]
    if not complete:
        state = 'checking'
    elif not good_dns:
        state = 'red'
    elif not requests or not any(r.get('code') for r in requests):
        state = 'red'
    elif len(good_dns) == len(answers) and len(good_http) == len(requests):
        state = 'green'
    else:
        state = 'yellow'
    issues = [f'DNS {r["server"]}: {r["detail"]}' for r in answers if not r['ok']]
    issues += [r['detail'] for r in requests if not r['ok']]
    return {
        **service, 'state': state, 'dns_ok': len(good_dns), 'dns_total': len(answers),
        'addresses': sorted({ip for r in good_dns for ip in r['addresses']}),
        'http_codes': sorted({r['code'] for r in requests if r.get('code')}),
        'dns_ms': median([r['ms'] for r in good_dns]),
        'tcp_ms': median([r.get('timings', {}).get('tcp_ms') for r in requests]),
        'tls_ms': median([r.get('timings', {}).get('tls_ms') for r in requests]),
        'https_ms': median([r.get('timings', {}).get('total_ms') for r in requests]),
        'tcp_ok': any(r.get('tcp_ok', False) for r in requests),
        'tls_ok': any(r.get('tls_ok', False) for r in requests),
        'issues': issues,
        'detail': issues[0] if issues else ('DNS и HTTPS отвечают' if state == 'green' else 'Ожидается проверка HTTPS'),
    }


def summary(result):
    services = result.get('services', [])
    ai = [s for s in services if s.get('role') == 'ai']
    dns = result['dns']
    requests = result['https']
    servers = result.get('tested_servers', [])
    return {
        'services_ok': sum(s['state'] == 'green' for s in services), 'services_total': len(services),
        'ai_ok': sum(s['state'] == 'green' for s in ai), 'ai_total': len(ai),
        'dns_servers_ok': sum(all(r['ok'] for r in dns if r['server'] == server) and any(r['server'] == server for r in dns) for server in servers),
        'dns_servers_total': len(servers),
        'dns_ms': median([r['ms'] for r in dns if r['ok']]),
        'tcp_ms': median([r.get('timings', {}).get('tcp_ms') for r in requests]),
        'https_ms': median([r.get('timings', {}).get('total_ms') for r in requests if r.get('code') and r.get('tls_ok')]),
    }
