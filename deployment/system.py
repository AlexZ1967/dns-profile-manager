"""Privileged installation transaction. Persistent Dispatcher never imports this project."""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import uuid

DISPATCHER = '/etc/NetworkManager/dispatcher.d/90-dns-profile-manager'
LEGACY_DISPATCHER = '/etc/NetworkManager/dispatcher.d/90-dns-route-refresh'
ROOT_CONFIG = '/etc/dns-profile-manager/dispatcher.json'
NM_CONFIG = '/etc/NetworkManager/conf.d/90-dns-profile-manager.conf'
JOURNAL = '/var/lib/dns-profile-manager/installation.json'
PROFILE = '/etc/systemd/resolved.conf.d/90-dns-profile-manager.conf'
LEGACY_PROFILE = '/etc/systemd/resolved.conf.d/90-alex-dns-profile.conf'
LEGACY_DNS_PROFILES = tuple('/etc/systemd/resolved.conf.d/'+name for name in ('dns-ai.conf','dagami.conf','magicdns.conf'))
RESOLV = '/etc/resolv.conf'
RESOLVED_STUB = '/run/systemd/resolve/stub-resolv.conf'
ROUTE_LOCK = '/run/lock/nm-dns-primary-route.lock'
FIELDS = ('ipv4.ignore-auto-dns','ipv4.dns','ipv6.ignore-auto-dns','ipv6.dns')
PACKAGES = ['python3-gi','gir1.2-gtk-3.0','knot-dnsutils','systemd-resolved','curl','dialog','zenity','iproute2','util-linux','ncurses-bin','ca-certificates']
ENV = {**os.environ, 'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}


class SetupError(Exception):
    pass


def command(args, check=True):
    import sys
    apt='apt-get' in args[0]
    result=subprocess.run(args,stdout=sys.stderr if apt else subprocess.PIPE,stderr=None if apt else subprocess.PIPE,text=True,timeout=600 if apt else 40,env=ENV)
    if check and result.returncode:
        raise SetupError(' '.join(args[:4])+': '+(result.stderr or result.stdout or "Ошибка установки пакетов")[-1600:])
    return result


def snapshot(path):
    if not os.path.lexists(path):return {'kind':'absent'}
    st=path.lstat()
    if stat.S_ISLNK(st.st_mode):return {'kind':'symlink','target':os.readlink(path)}
    if not stat.S_ISREG(st.st_mode):raise SetupError('Необычный системный файл: '+str(path))
    if st.st_size>1024*1024:raise SetupError('Слишком большой системный файл: '+str(path))
    return {'kind':'file','data':base64.b64encode(path.read_bytes()).decode(),'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid}


def atomic(path, data, mode=0o644):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),mode);stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)


def restore(path, data):
    if data['kind']=='absent':
        if os.path.lexists(path):path.unlink()
    elif data['kind']=='file':
        atomic(path,base64.b64decode(data['data']),data['mode'])
        if os.geteuid()==0:os.chown(path,data.get('uid',0),data.get('gid',0))
    elif data['kind']=='symlink':
        path.parent.mkdir(parents=True,exist_ok=True)
        temporary=path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
        try:temporary.symlink_to(data['target']);os.replace(temporary,path)
        finally:
            if os.path.lexists(temporary):temporary.unlink()
    else:raise SetupError('Неизвестный тип снимка')


class SystemDeployment:
    def __init__(self, root=Path('/'), run=command, asset=None):
        self.root=Path(root)
        self.run=run
        self.asset=asset or Path(__file__).with_name('dispatcher.py')

    def path(self, name):
        p=self.root/name.lstrip('/')
        for parent in p.parents:
            if parent==self.root:break
            if parent.is_symlink():raise SetupError('Системный каталог является ссылкой: '+str(parent))
        return p

    @contextlib.contextmanager
    def locked(self, name):
        path=self.path(name);path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'r+') as stream:
            st=os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or self.root==Path('/') and (st.st_uid!=0 or st.st_mode&0o022):
                raise SetupError('Небезопасный системный lock')
            fcntl.flock(stream,fcntl.LOCK_EX)
            yield

    def save(self, journal):
        path=self.path(JOURNAL);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        atomic(path,json.dumps(journal,ensure_ascii=False,indent=2).encode(),0o600)

    def read(self):
        path=self.path(JOURNAL)
        if not path.exists():return None
        st=path.lstat()
        if not stat.S_ISREG(st.st_mode) or self.root==Path('/') and (st.st_uid!=0 or st.st_mode&0o077):
            raise SetupError('Небезопасный журнал установки')
        return json.loads(path.read_text())

    def verify_request(self, plan):
        import dns_network
        dns_network.validate(plan['network'])
        uuid.UUID(plan['installation_id'])
        if plan['network'].get('installation_id')!=plan['installation_id']:raise SetupError('ID установки не совпадает')
        if not Path(plan['project']).is_absolute() or int(plan['owner_uid'])<=0:raise SetupError('Некорректный владелец / проект')
        if self.root==Path('/') and str(plan['owner_uid'])!=os.environ.get('SUDO_UID'):
            raise SetupError('Запускайте install от обычного пользователя через его sudo')
        existing=self.read()
        if existing and (existing['installation_id']!=plan['installation_id'] or existing['owner_uid']!=plan['owner_uid']):
            raise SetupError('На машине уже есть другая установка DNS Profile Manager')
        if existing and existing["network"] != plan["network"]:
            raise SetupError("Для изменения набора подключений сначала выполните ./uninstall, затем ./install.")
        return existing

    def service_state(self):
        enabled=self.run(['/usr/bin/systemctl','is-enabled','systemd-resolved.service'],check=False)
        active=self.run(['/usr/bin/systemctl','is-active','systemd-resolved.service'],check=False)
        if enabled.stdout.strip() in ('masked','masked-runtime'):raise SetupError('systemd-resolved замаскирован. Автоматическое снятие маски не выполняется.')
        return {'enabled':enabled.returncode==0,'active':active.returncode==0}

    def network_snapshot(self, connections):
        result={}
        for connection in connections:
            values={}
            kind=self.run(['/usr/bin/nmcli','-g','connection.type','connection','show',connection['uuid']]).stdout.strip()
            if kind!=connection['type']:raise SetupError('Тип подключения изменился: '+connection['uuid'])
            for field in FIELDS:
                value=self.run(['/usr/bin/nmcli','--escape','no','-g',field,'connection','show',connection['uuid']]).stdout.strip()
                values[field]='' if value=='--' else value
            result[connection['uuid']]={'type':kind,'values':values}
        return result

    def check_files(self, journal):
        for name, expected in journal.get('installed',{}).items():
            if name==journal['network']['profile_file']:continue
            actual=snapshot(self.path(name))
            # During rollback a step may still have its original value.
            if actual!=expected and actual!=journal['before'].get(name):
                raise SetupError('Системный файл изменён вне приложения, не перезаписываю: '+name)
        profile=journal['network']['profile_file'];current=snapshot(self.path(profile));original=journal['before'][profile]
        if current['kind']!='absent' and current!=original:
            marker=('# DNS Profile Manager: '+journal['installation_id']).encode()
            if current['kind']!='file' or marker not in base64.b64decode(current['data']).splitlines()[:1]:
                raise SetupError('Управляемый DNS-профиль изменён другим инструментом: '+profile)

    def install(self, plan):
        previous=self.verify_request(plan)
        if self.run(['/usr/bin/systemctl','is-active','NetworkManager.service'],check=False).returncode:
            raise SetupError('Нужен активный NetworkManager. Подключите сеть средствами системы.')
        if previous:
            self.check_files(previous)
            journal=previous
        else:
            profile=plan['network']['profile_file']
            names=[DISPATCHER,ROOT_CONFIG,NM_CONFIG,RESOLV,profile]
            if plan.get('adopt_existing'):names.extend([LEGACY_DISPATCHER,*LEGACY_DNS_PROFILES])
            for name in (DISPATCHER,ROOT_CONFIG,NM_CONFIG):
                if os.path.lexists(self.path(name)):raise SetupError('Файл уже существует вне журнала установки: '+name)
            if self.path(LEGACY_DISPATCHER).exists() and not plan.get('adopt_existing'):
                raise SetupError('Найден прежний Dispatcher. Для его переноса нужен --adopt-existing.')
            if self.path(profile).exists() and not (plan.get('adopt_existing') and profile==LEGACY_PROFILE):
                raise SetupError('Управляемый путь уже занят: '+profile)
            for other in self.path('/etc/systemd/resolved.conf.d').glob('*.conf') if self.path('/etc/systemd/resolved.conf.d').exists() else []:
                adopted=plan.get('adopt_existing') and other in [self.path(name) for name in LEGACY_DNS_PROFILES]
                if other!=self.path(profile) and not adopted and re_dns(other):
                    raise SetupError('Найдена другая глобальная настройка DNS: '+str(other))
            main=self.path('/etc/systemd/resolved.conf')
            if main.exists() and re_dns(main):raise SetupError('В resolved.conf уже задан DNS. Согласуйте его перед установкой.')
            journal={'version':1,'installation_id':plan['installation_id'],'owner_uid':plan['owner_uid'],'project':plan['project'],
                     'network':plan['network'],'before':{name:snapshot(self.path(name)) for name in names},'installed':{},
                     'service_before':self.service_state(),'connections_before':self.network_snapshot(plan['network']['connections']), 'phase':'preparing'}
            self.save(journal)
        try:
            missing=plan.get('missing_packages',[])
            if any(p not in PACKAGES for p in missing):raise SetupError('Недопустимый пакет')
            if missing:
                if not plan.get('install_dependencies'):raise SetupError('Недостающие пакеты: '+', '.join(missing))
                self.run(['/usr/bin/apt-get','update'])
                self.run(['/usr/bin/apt-get','install','-y',*missing])
            with self.locked(ROUTE_LOCK):
                if plan.get('adopt_existing'):
                    for name in (LEGACY_DISPATCHER,*LEGACY_DNS_PROFILES):
                        if os.path.lexists(self.path(name)):self.path(name).unlink()
                        journal['installed'][name]={'kind':'absent'};self.save(journal)
                contents={
                    ROOT_CONFIG:json.dumps(plan['network'],ensure_ascii=False,indent=2).encode(),
                    NM_CONFIG:('# DNS Profile Manager: '+plan['installation_id']+'\n[main]\ndns=systemd-resolved\n').encode(),
                    DISPATCHER:self.asset.read_bytes(),
                }
                for name, content in contents.items():
                    atomic(self.path(name),content,0o755 if name==DISPATCHER else 0o644)
                    journal['installed'][name]=snapshot(self.path(name));self.save(journal)
                self.run(['/usr/bin/systemctl','enable','--now','systemd-resolved.service'])
                resolv=self.path(RESOLV)
                correct=resolv.is_symlink() and os.path.normpath(os.path.join('/etc',os.readlink(resolv)))==RESOLVED_STUB
                if not correct:restore(resolv,{'kind':'symlink','target':RESOLVED_STUB})
                journal['installed'][RESOLV]=snapshot(resolv);self.save(journal)
                self.run(['/usr/bin/nmcli','general','reload'])
            self.run(['/usr/bin/python3',DISPATCHER,'--sync'])
            self.run(['/usr/bin/resolvectl','status'])
            journal['phase']='installed';journal['network']=plan['network'];self.save(journal)
            return journal
        except Exception as exc:
            journal['phase']='failed';journal['error']=str(exc);self.save(journal)
            try:self.restore_system(journal);journal['phase']='rolled-back';self.save(journal)
            except Exception as rollback:journal['rollback_error']=str(rollback);self.save(journal)
            raise SetupError('Установка не завершена: '+str(exc))

    def restore_system(self, journal):
        self.check_files(journal)
        with self.locked(ROUTE_LOCK):
            # Remove our hook before restoring connection settings; queued callbacks recheck config under lock.
            if os.path.lexists(self.path(DISPATCHER)):self.path(DISPATCHER).unlink()
            if os.path.lexists(self.path(ROOT_CONFIG)):self.path(ROOT_CONFIG).unlink()
            profile=journal['network']['profile_file']
            restore(self.path(profile),journal['before'][profile])
            for name in (NM_CONFIG,RESOLV):restore(self.path(name),journal['before'][name])
            self.run(['/usr/bin/nmcli','general','reload'])
            from deployment.dispatcher import active
            actives={row['uuid']:row['interface'] for row in active(lambda args:self.run(args).stdout.strip())}
            for ident,before in journal['connections_before'].items():
                exists=self.run(['/usr/bin/nmcli','-g','connection.type','connection','show',ident],check=False)
                if exists.returncode:continue
                if exists.stdout.strip()!=before['type']:raise SetupError('Тип прежнего подключения изменился: '+ident)
                args=['/usr/bin/nmcli','connection','modify',ident]
                for field,value in before['values'].items():args.extend([field,value])
                self.run(args)
                if ident in actives:self.run(['/usr/bin/nmcli','device','reapply',actives[ident]])
            was=journal['service_before']
            if was['active']:
                self.run(['/usr/bin/systemctl','restart','systemd-resolved.service'])
            else:self.run(['/usr/bin/systemctl','stop','systemd-resolved.service'],check=False)
            if not was['enabled']:self.run(['/usr/bin/systemctl','disable','systemd-resolved.service'],check=False)
            # Restore any pre-existing Dispatcher only after our DNS cleanup is complete.
            for name in (DISPATCHER,ROOT_CONFIG,LEGACY_DISPATCHER,*LEGACY_DNS_PROFILES):
                if name in journal['before']:restore(self.path(name),journal['before'][name])
        return journal

    def finish(self, journal, phase):
        journal['phase']=phase
        self.path(JOURNAL).unlink()
        for directory in ('/etc/dns-profile-manager','/var/lib/dns-profile-manager'):
            path=self.path(directory)
            if path.is_dir() and not any(path.iterdir()):path.rmdir()
        return journal

    def rollback(self, plan):
        """Installation failure only: restore exactly what existed before installation."""
        journal=self.verify_request(plan)
        if journal is None:return {'phase':'rolled-back','installation_id':plan['installation_id']}
        self.restore_system(journal)
        return self.finish(journal,'rolled-back')

    def uninstall(self, plan):
        """Explicit uninstall always leaves automatic provider DNS, never an old profile."""
        journal=self.verify_request(plan)
        if journal is None:return {'phase':'uninstalled','installation_id':plan['installation_id']}
        self.check_files(journal)
        journal['phase']='uninstalling';self.save(journal)
        with self.locked(ROUTE_LOCK):
            # Queued Dispatcher callbacks recheck config after acquiring this same lock.
            names=[DISPATCHER,ROOT_CONFIG,NM_CONFIG,journal['network']['profile_file']]
            names.extend(name for name in (LEGACY_DISPATCHER,*LEGACY_DNS_PROFILES) if name in journal['before'])
            for name in names:
                if os.path.lexists(self.path(name)):self.path(name).unlink()
            # Keep the OS resolver working in DHCP mode, including a formerly clean machine.
            restore(self.path(RESOLV),{'kind':'symlink','target':RESOLVED_STUB})
            self.run(['/usr/bin/systemctl','enable','--now','systemd-resolved.service'])
            self.run(['/usr/bin/systemctl','restart','systemd-resolved.service'])
            self.run(['/usr/bin/nmcli','general','reload'])
            from deployment.dispatcher import active
            actives={row['uuid']:row['interface'] for row in active(lambda args:self.run(args).stdout.strip())}
            for ident,before in journal['connections_before'].items():
                exists=self.run(['/usr/bin/nmcli','-g','connection.type','connection','show',ident],check=False)
                if exists.returncode:continue
                if exists.stdout.strip()!=before['type']:raise SetupError('Тип подключения изменился: '+ident)
                self.run(['/usr/bin/nmcli','connection','modify',ident,
                          'ipv4.ignore-auto-dns','no','ipv4.dns','',
                          'ipv6.ignore-auto-dns','no','ipv6.dns',''])
                if ident in actives:self.run(['/usr/bin/nmcli','device','reapply',actives[ident]])
            self.run(['/usr/bin/resolvectl','reset-server-features'])
            self.run(['/usr/bin/resolvectl','flush-caches'])
            self.run(['/usr/bin/resolvectl','status'])
        journal['result']='provider-dns-dhcp'
        return self.finish(journal,'uninstalled')


def re_dns(path):
    import re
    return bool(re.search(r'^\s*DNS\s*=\s*[^\s#]+',path.read_text(),re.M))
