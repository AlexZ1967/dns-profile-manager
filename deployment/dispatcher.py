#!/usr/bin/python3
# DNS Profile Manager managed Dispatcher. Installed as a root-owned copy.
"""Never import or source a file from the user's project or home directory."""
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import syslog
import tempfile
import time

CONFIG = Path('/etc/dns-profile-manager/dispatcher.json')
LOCK = Path('/run/lock/nm-dns-primary-route.lock')
STATE = Path('/run/nm-dns-primary-route.state')
PHYSICAL = {'802-3-ethernet', '802-11-wireless'}
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C'}


def call(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15, env=ENV)
    if result.returncode:
        raise RuntimeError(' '.join(args[:3])+': '+result.stderr.strip())
    return result.stdout.strip()


def active(run=call):
    rows = []
    for line in run(['/usr/bin/nmcli','-t','--escape','no','-f','UUID,TYPE,DEVICE','connection','show','--active']).splitlines():
        fields = line.split(':',2)
        if len(fields)==3 and fields[1] in PHYSICAL and fields[2] and fields[2]!='--':
            rows.append({'uuid':fields[0], 'type':fields[1], 'interface':fields[2]})
    return rows


def read_config(path=CONFIG, check_owner=True):
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or check_owner and (st.st_uid!=0 or st.st_mode & 0o022):
        raise RuntimeError('Dispatcher config must be a root-owned non-writable regular file')
    data=json.loads(path.read_text())
    if data.get('version')!=1 or data.get('profile_file') not in {
        '/etc/systemd/resolved.conf.d/90-dns-profile-manager.conf',
        '/etc/systemd/resolved.conf.d/90-alex-dns-profile.conf'}:
        raise RuntimeError('Invalid Dispatcher configuration')
    for item in data['connections']:
        if item['type'] not in PHYSICAL or not re.fullmatch(r'[0-9a-fA-F-]{36}',item['uuid']):
            raise RuntimeError('Invalid allowed connection')
    return data


def synchronize(config, run=call, profile_path=None):
    allowed={item['uuid']:item for item in config['connections']}
    profile=Path(profile_path or config['profile_file'])
    managed=profile.is_file() and bool(re.search(r'^\s*DNS\s*=\s*[^\s#]+',profile.read_text(),re.M))
    ignore='yes' if managed else 'no'
    for item in active(run):
        spec=allowed.get(item['uuid'])
        if not spec or spec['type']!=item['type'] or spec.get('interface') and spec['interface']!=item['interface']:
            continue
        values=[]
        for key in ('ipv4.ignore-auto-dns','ipv6.ignore-auto-dns','ipv4.dns','ipv6.dns'):
            values.append(run(['/usr/bin/nmcli','-g',key,'connection','show',item['uuid']]))
        if values==[ignore,ignore,'','']:
            continue
        run(['/usr/bin/nmcli','connection','modify',item['uuid'],'ipv4.ignore-auto-dns',ignore,'ipv4.dns','',
             'ipv6.ignore-auto-dns',ignore,'ipv6.dns',''])
        run(['/usr/bin/nmcli','device','reapply',item['interface']])
        syslog.syslog(f'DNS synchronized on {item["interface"]}: global={managed}')


def refresh_route(run=call, state_file=STATE):
    try:
        route=json.loads(run(['/usr/bin/ip','-j','-4','route','get','1.1.1.1']) or '[]')
    except RuntimeError:
        route=[]
    current=(route[0].get('dev','')+'|'+route[0].get('gateway','direct')) if route else 'none'
    previous=state_file.read_text().strip() if state_file.exists() else ''
    if current!=previous:
        state_file.parent.mkdir(parents=True,exist_ok=True)
        fd,name=tempfile.mkstemp(prefix='.dns-route-',dir=state_file.parent)
        try:
            with os.fdopen(fd,'w') as stream:
                os.fchmod(stream.fileno(),0o644);stream.write(current+'\n')
            os.replace(name,state_file)
        finally:
            if os.path.exists(name):os.unlink(name)
        if current!='none':
            run(['/usr/bin/resolvectl','reset-server-features'])
            run(['/usr/bin/resolvectl','flush-caches'])
        syslog.syslog(f'Primary route: {previous or "unknown"} -> {current}')


def main():
    if os.geteuid()!=0:
        return 1
    syslog.openlog('dns-profile-manager')
    sync=sys.argv[1:]==['--sync']
    if not sync and (len(sys.argv)<3 or sys.argv[2] not in {'up','down','dhcp4-change','dhcp6-change'}):
        return 0
    try:
        config=read_config()
        if not sync:
            known={item['uuid'] for item in config['connections']}
            interface=sys.argv[1]
            if os.environ.get('CONNECTION_UUID') not in known and not any(item['uuid'] in known and item['interface']==interface for item in active()):
                return 0
        # Same lock used by the unprivileged CLI's sudo operations.
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'r+') as lock:
            st=os.fstat(lock.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
                raise RuntimeError('Unsafe Dispatcher lock')
            deadline=time.monotonic()+12
            while True:
                try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    if time.monotonic()>=deadline:raise RuntimeError('Dispatcher lock timeout')
                    time.sleep(0.1)
            if not CONFIG.exists():return 0
            config=read_config()
            synchronize(config)
            try:refresh_route()
            except (RuntimeError,ValueError):
                # No route during down is expected; DNS synchronization is still complete.
                syslog.syslog('No usable primary IPv4 route')
        return 0
    except Exception as exc:
        syslog.syslog(syslog.LOG_ERR,str(exc));return 1


if __name__=='__main__':raise SystemExit(main())
