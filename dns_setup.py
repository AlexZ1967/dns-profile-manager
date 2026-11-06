#!/usr/bin/python3
"""Install / uninstall DNS Profile Manager, retaining project-local data and backups."""
import argparse
import contextlib
import datetime
import fcntl
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import uuid

import dns_manager as manager
import dns_network
import integrate
from deployment.system import SystemDeployment, SetupError, PACKAGES, PROFILE, LEGACY_PROFILE, LEGACY_DISPATCHER


def invoke(args, check=True, **kwargs):
    result=subprocess.run(args,capture_output=True,text=True,timeout=30,**kwargs)
    if check and result.returncode:raise SetupError((result.stderr or result.stdout).strip())
    return result


def missing_packages(run=invoke):
    result=run(['/usr/bin/dpkg-query','-W','-f=${Package}\t${db:Status-Status}\n',*PACKAGES],check=False)
    installed={line.split('\t')[0] for line in result.stdout.splitlines() if line.endswith('\tinstalled')}
    return [package for package in PACKAGES if package not in installed]


def discover_connections(run=invoke):
    result=[]
    rows=run(['/usr/bin/nmcli','-t','--escape','no','-f','UUID,TYPE','connection','show']).stdout
    for line in rows.splitlines():
        fields=line.split(':',1)
        if len(fields)!=2 or fields[1] not in dns_network.TYPES:continue
        name=run(['/usr/bin/nmcli','--escape','no','-g','connection.id','connection','show',fields[0]]).stdout.strip()
        result.append({'uuid':fields[0],'type':fields[1],'interface':'','name':name})
    if not result:raise SetupError('Сначала создайте хотя бы одно Ethernet/Wi-Fi подключение средствами NetworkManager.')
    return result


def system_call(operation, plan):
    command=['sudo','/usr/bin/python3',str(manager.ROOT/'dns_setup.py'),'_system',operation]
    result=subprocess.run(command,input=json.dumps(plan),stdout=subprocess.PIPE,text=True)
    try:payload=json.loads(result.stdout)
    except ValueError:raise SetupError('Системный установщик не вернул результат. Проверьте сообщения sudo.')
    if result.returncode:
        error=SetupError(payload.get('error','Ошибка системной установки'))
        error.journal=payload.get('journal')
        raise error
    return payload


class UserDeployment:
    def __init__(self, project=manager.ROOT, home=None, run=invoke, system=system_call):
        self.project=Path(project).resolve();self.home=Path.home() if home is None else Path(home)
        self.local=self.project/'.local';self.config=self.local/'config';self.cache=self.local/'cache'
        self.manifest=self.local/'installation.json';self.run=run;self.system=system
        self.aliases=self.home/'.bash_aliases';self.bashrc=self.home/'.bashrc'

    def read(self):
        return json.loads(self.manifest.read_text()) if self.manifest.exists() else None

    def save(self, record):
        self.local.mkdir(parents=True,exist_ok=True,mode=0o700)
        manager.atomic_write(self.manifest,json.dumps(record,ensure_ascii=False,indent=2)+'\n')

    def hook(self):
        entry=shlex.quote(str(self.project/'shell/dns.bash'))
        return f'{integrate.HOOK_START}\n[[ ! -r {entry} ]] || source {entry}\n{integrate.HOOK_END}\n'

    def backup(self, name, content):
        stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
        path=self.local/'backups'/(name+'.'+stamp)
        manager.atomic_write(path,content)
        return str(path)

    def prepare_aliases(self):
        original=self.aliases.read_text() if self.aliases.exists() else ''
        if integrate.HOOK_START in original or integrate.LEGACY_START in original:
            start,end,legacy=integrate.owned_region(original)
            if legacy is not None:integrate.declarations(legacy)
            updated=original[:start]+self.hook()+original[end:]
        else:
            updated=original+('' if not original or original.endswith('\n') else '\n')+self.hook()
        integrate.syntax(updated,str(self.aliases))
        return original,updated

    def cli_targets(self, data):
        names=['dnsctl','dns-gui','dns-menu',*manager.command_map(data)]
        targets={name:self.project/(name if name in ('dnsctl','dns-gui','dns-menu') else 'dns-provider-command') for name in names}
        for name,target in targets.items():
            path=self.home/'.local/bin'/name
            if os.path.lexists(path) and (not path.is_symlink() or path.resolve()!=target.resolve()):
                raise SetupError('CLI-путь занят другой программой: '+str(path))
        return targets

    def make_plan(self, options):
        current=self.read()
        if current and current.get('machine_id')!=manager.machine_identifier():current=None
        ident=current['installation_id'] if current and current.get('state')!='uninstalled' else str(uuid.uuid4())
        connections=discover_connections(self.run)
        if options.connection:
            selected=set(options.connection)
            if not selected<={c['uuid'] for c in connections}:raise SetupError('Не все --connection относятся к известным Ethernet/Wi-Fi.')
            connections=[c for c in connections if c['uuid'] in selected]
        profile=LEGACY_PROFILE if options.adopt_existing and Path(LEGACY_PROFILE).exists() else PROFILE
        if current and current.get('state')!='uninstalled':
            network=current['plan']['network']
            if not options.connection:connections=network['connections']
            profile=network['profile_file']
        network={'version':1,'installation_id':ident,'connections':connections,'profile_file':profile,
                 'lock_file':dns_network.LOCK,'state_file':dns_network.STATE}
        dns_network.validate(network)
        data_path=self.config/'providers.json'
        legacy=self.home/'.config/dns-manager/providers.json'
        data=manager.validate_config(json.loads((data_path if data_path.exists() else legacy if legacy.exists() else self.project/'providers.default.json').read_text()))
        self.cli_targets(data);self.prepare_aliases()
        desktop=self.home/'.local/share/applications/dns-profile-manager.desktop'
        if desktop.exists() and '# DNS Profile Manager' not in desktop.read_text():raise SetupError('Desktop-файл занят другой программой: '+str(desktop))
        plan={'installation_id':ident,'owner_uid':os.getuid(),'project':str(self.project),'network':network,
              'adopt_existing':bool(options.adopt_existing or current and current.get('plan',{}).get('adopt_existing')),
              'install_dependencies':options.install_dependencies,'missing_packages':missing_packages(self.run)}
        return plan,data

    def describe(self, plan):
        print('Проект:',self.project)
        print('Настройки и резервные копии:',self.local)
        print('Подключения:')
        for item in plan['network']['connections']:print(' ',item['uuid'],item['type'],item.get('name',''))
        print('Управляемый DNS:',plan['network']['profile_file'])
        print('Установятся: CLI-ссылки, подключение Bash, ярлык GUI, Dispatcher и интеграция NetworkManager/resolved.')
        print('На чистой установке начальный режим — DNS провайдера; существующий профиль сохраняется только при --adopt-existing.')
        if plan['missing_packages']:print('Недостающие пакеты:',', '.join(plan['missing_packages']))
        if Path(LEGACY_DISPATCHER).exists() and not plan['adopt_existing']:
            print('Обнаружен прежний Dispatcher: для его сохранения и переноса нужен --adopt-existing.')

    def localize(self, record):
        for category in ('config','cache'):
            old=self.home/('.config' if category=='config' else '.cache')/'dns-manager'
            target=self.local/category
            if old.is_symlink():
                if old.resolve()!=target.resolve():raise SetupError('Неизвестная ссылка: '+str(old))
            elif old.exists():
                if not old.is_dir():raise SetupError('Ожидался каталог: '+str(old))
                for path in old.rglob('*'):
                    relative=path.relative_to(old);dest=target/relative
                    if path.is_symlink():raise SetupError('Неожиданная ссылка в прежних данных: '+str(path))
                    if path.is_file() and dest.exists() and dest.read_bytes()!=path.read_bytes():raise SetupError('Конфликт локальных данных: '+str(dest))
                if category=='cache' and not target.exists():
                    shutil.move(str(old),str(target))
                    old.parent.mkdir(parents=True,exist_ok=True);old.symlink_to(target)
                    record.setdefault('compatibility_links',{})[str(old)]=str(target)
                    self.save(record);continue
                shutil.copytree(old,target,dirs_exist_ok=True)
                archive=self.local/'backups'/('previous-'+category+'-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
                archive.parent.mkdir(parents=True,exist_ok=True);shutil.move(str(old),str(archive))
            target.mkdir(parents=True,exist_ok=True,mode=0o700)
            if not os.path.lexists(old):
                old.parent.mkdir(parents=True,exist_ok=True);old.symlink_to(target)
            record.setdefault('compatibility_links',{})[str(old)]=str(target)
            self.save(record)

    def system_backup(self, name, result):
        text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
        self.backup(name+'.json',text)
        manager.atomic_write(self.local/'backups'/(name+'.json'),text)

    def install_user(self, record, data):
        manager.atomic_write(self.config/'commands.bash','\n'.join(manager.command_routes(data, self.project))+'\n')
        original,updated=self.prepare_aliases()
        if original!=updated:
            self.backup('bash_aliases',original)
            manager.atomic_write(self.aliases,updated,self.aliases.stat().st_mode&0o777 if self.aliases.exists() else 0o644)
        record['aliases_hook']=self.hook();self.save(record)
        bashrc=self.bashrc.read_text() if self.bashrc.exists() else ''
        if '.bash_aliases' not in bashrc and self.hook() not in bashrc:
            self.backup('bashrc',bashrc)
            hook=self.hook().replace('DNS Profile Manager >>>','DNS Profile Manager loader >>>').replace('DNS Profile Manager <<<','DNS Profile Manager loader <<<')
            manager.atomic_write(self.bashrc,bashrc+('' if not bashrc or bashrc.endswith('\n') else '\n')+hook,0o644)
            record['bashrc_hook']=hook;self.save(record)
        for name,target in self.cli_targets(data).items():
            path=self.home/'.local/bin'/name;path.parent.mkdir(parents=True,exist_ok=True)
            if not os.path.lexists(path):path.symlink_to(target)
        desktop=self.home/'.local/share/applications/dns-profile-manager.desktop'
        desktop.parent.mkdir(parents=True,exist_ok=True)
        executable=str(self.project/'dns-gui').replace('\\','\\\\').replace('"','\\"').replace('%','%%').replace('`','\\`').replace('$','\\$')
        text=f'# DNS Profile Manager {record["installation_id"]}\n[Desktop Entry]\nType=Application\nName=DNS Profile Manager\nComment=DNS profiles and diagnostics\nExec="{executable}"\nIcon=network-workgroup\nTerminal=false\nCategories=Settings;Network;\n'
        manager.atomic_write(desktop,text,0o644);record['desktop']={'path':str(desktop),'content':text};self.save(record)

    def install(self, options):
        if os.geteuid()==0:raise SetupError('Запускайте ./install обычным пользователем; sudo будет запрошен для системной части.')
        plan,data=self.make_plan(options);self.describe(plan)
        if options.dry_run:return
        if plan['missing_packages'] and not options.install_dependencies:
            raise SetupError('Зависимости не установлены. Запустите ./install --install-dependencies для явного разрешения их установки.')
        self.local.mkdir(parents=True,exist_ok=True,mode=0o700)
        operation=self.cache if self.cache.exists() else self.home/'.cache/dns-manager'
        with manager.lock(self.local/'setup.lock'), manager.lock(operation/'operation.lock'):
            existing=self.read()
            if existing and existing.get('machine_id')!=manager.machine_identifier():
                self.backup('installation-from-other-machine.json',json.dumps(existing,ensure_ascii=False,indent=2))
                existing=None
            record=existing or {}
            record.update(installation_id=plan['installation_id'],plan=plan,state='preparing',project=str(self.project),machine_id=manager.machine_identifier())
            self.save(record)
            try:
                print('1/3: переношу пользовательские данные в проект…',flush=True)
                self.localize(record)
                record['system_installed']=False;self.save(record)
                if not (self.config/'providers.json').exists():manager.atomic_write(self.config/'providers.json',json.dumps(data,ensure_ascii=False,indent=2)+'\n')
                data=manager.validate_config(json.loads((self.config/'providers.json').read_text()))
                previous=self.config/'network.json'
                if previous.exists():self.backup('network.json',previous.read_text())
                manager.atomic_write(previous,json.dumps(plan['network'],ensure_ascii=False,indent=2)+'\n')
                print('2/3: устанавливаю системную интеграцию (sudo)…',flush=True)
                result=self.system('install',plan)
                self.system_backup('system-installation',result)
                record['system_installed']=True;self.save(record)
                print('3/3: подключаю команды Bash, CLI и ярлык GUI…',flush=True)
                self.install_user(record,data)
                record['state']='installed';self.save(record)
                print('Установка завершена. Откройте новый терминал или выполните source ~/.bash_aliases.')
            except Exception as exc:
                if getattr(exc,'journal',None):self.system_backup('system-installation',exc.journal)
                if record.get('system_installed'):
                    try:
                        rollback=self.system('rollback',plan)
                        self.system_backup('system-rollback',rollback)
                        self.remove_user(record)
                        record['system_installed']=False
                    except Exception as rollback:
                        record['rollback_error']=str(rollback)
                record['state']='failed';record['error']=str(exc);self.save(record)
                raise

    def remove_user(self, record):
        for path,hook in [(self.aliases,record.get('aliases_hook')),(self.bashrc,record.get('bashrc_hook'))]:
            if not hook or not path.exists():continue
            original=path.read_text()
            if hook in original:
                self.backup(path.name.lstrip('.')+'-before-uninstall',original)
                manager.atomic_write(path,original.replace(hook,'',1),path.stat().st_mode&0o777)
            elif (integrate.HOOK_START in original or 'DNS Profile Manager loader >>>' in original):
                raise SetupError('Блок Bash изменён вручную: '+str(path))
        binary=self.home/'.local/bin'
        if binary.exists():
            expected={(self.project/name).resolve() for name in ('dnsctl','dns-provider-command','dns-gui','dns-menu')}
            for path in binary.iterdir():
                if path.is_symlink() and path.resolve() in expected:path.unlink()
        desktop=record.get('desktop',{})
        if desktop:
            path=Path(desktop['path'])
            if path!=self.home/'.local/share/applications/dns-profile-manager.desktop':raise SetupError('Неверный путь desktop в журнале')
            if path.exists() and path.read_text()==desktop['content']:path.unlink()
            elif path.exists():raise SetupError('Desktop-файл изменён вручную: '+str(path))
        for name,target in record.get('compatibility_links',{}).items():
            path=Path(name)
            allowed={self.home/'.config/dns-manager':self.config,self.home/'.cache/dns-manager':self.cache}
            if path not in allowed or Path(target)!=allowed[path]:raise SetupError('Неверный путь совместимости в журнале')
            if path.is_symlink() and path.resolve()==Path(target).resolve():path.unlink()
            elif os.path.lexists(path):raise SetupError('Путь совместимости изменён вручную: '+str(path))

    def uninstall(self, options):
        if os.geteuid()==0:raise SetupError('Запускайте ./uninstall обычным пользователем.')
        record=self.read()
        if not record or record.get('state')=='uninstalled' or record.get('machine_id')!=manager.machine_identifier():
            print('Активная установка не найдена. Директория проекта сохранена.');return
        print('Будут удалены наш и перенесённый старый Dispatcher, ссылки CLI/GUI и Bash-подключение. Ручные DNS отключатся; останется DNS провайдера от DHCP.')
        print('Проект, конфиги и резервные копии остаются:',self.project)
        if options.dry_run:return
        with manager.lock(self.local/'setup.lock'), manager.lock(self.cache/'operation.lock'):
            record['state']='uninstalling';self.save(record)
            result=self.system('uninstall',record['plan'])
            self.system_backup('system-uninstalled',result)
            self.remove_user(record)
            record['state']='uninstalled';self.save(record)
            print('Удаление завершено. Проект и данные сохранены. Закройте старые терминалы, чтобы убрать загруженные функции из памяти.')


def main():
    parser=argparse.ArgumentParser(description='Установка и удаление DNS Profile Manager')
    sub=parser.add_subparsers(dest='operation',required=True)
    install=sub.add_parser('install');install.add_argument('--dry-run',action='store_true');install.add_argument('--install-dependencies',action='store_true');install.add_argument('--adopt-existing',action='store_true');install.add_argument('--connection',action='append')
    uninstall=sub.add_parser('uninstall');uninstall.add_argument('--dry-run',action='store_true')
    sub.add_parser('status',help=argparse.SUPPRESS)
    internal=sub.add_parser('_system',help=argparse.SUPPRESS);internal.add_argument('action',choices=['install','uninstall','rollback'])
    args=parser.parse_args()
    if args.operation=='_system':
        if os.geteuid()!=0:raise SystemExit('Системная часть требует sudo.')
        engine=SystemDeployment()
        try:
            plan=json.load(sys.stdin)
            with engine.locked('/run/lock/dns-profile-manager-setup.lock'):
                result=getattr(engine,args.action)(plan)
            print(json.dumps(result,ensure_ascii=False));return
        except Exception as exc:
            print(json.dumps({'error':str(exc),'journal':engine.read()},ensure_ascii=False));raise SystemExit(1)
    try:
        deployment=UserDeployment()
        if args.operation=='status':manager.require_installation()
        elif args.operation=='install':deployment.install(args)
        else:deployment.uninstall(args)
    except (SetupError,manager.ManagerError,OSError,ValueError,subprocess.SubprocessError) as exc:
        raise SystemExit('Ошибка: '+str(exc))


if __name__=='__main__':main()
