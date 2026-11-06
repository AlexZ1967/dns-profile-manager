"""Deployment checks use a fake filesystem and commands, never the host network."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import dns_manager as manager
import dns_network
from dns_setup import UserDeployment
from deployment import dispatcher
from deployment.system import SystemDeployment, SetupError, DISPATCHER, ROOT_CONFIG, NM_CONFIG, JOURNAL, RESOLV, PROFILE, LEGACY_PROFILE, LEGACY_DISPATCHER, LEGACY_DNS_PROFILES, RESOLVED_STUB, FIELDS, snapshot

UUID='00000000-0000-0000-0000-000000000001'
ID='00000000-0000-0000-0000-000000000002'


def network():
    return {'version':1,'installation_id':ID,'connections':[{'uuid':UUID,'type':'802-3-ethernet','interface':'','name':'Ethernet'}],
            'profile_file':PROFILE,'lock_file':dns_network.LOCK,'state_file':dns_network.STATE}


class FakeCommands:
    def __init__(self):
        self.calls=[];self.values=dict(zip(FIELDS,['no','8.8.8.8','no','']))
        self.service_active=False;self.service_enabled=False;self.fail_sync=False;self.fail_general_reload=False

    def __call__(self,args,check=True):
        self.calls.append(args);text='';code=0
        if 'systemctl' in args[0]:
            op=args[1]
            if op=='is-active':
                yes=args[-1]=='NetworkManager.service' or self.service_active
                text='active' if yes else 'inactive';code=0 if yes else 3
            elif op=='is-enabled':text='enabled' if self.service_enabled else 'disabled';code=0 if self.service_enabled else 1
            elif op=='enable':self.service_active=True;self.service_enabled=True
            elif op=='stop':self.service_active=False
            elif op=='disable':self.service_enabled=False
            elif op=='restart':self.service_active=True
        elif 'nmcli' in args[0]:
            if args[1:]==['general','reload'] and self.fail_general_reload:
                self.fail_general_reload=False
                raise SetupError('simulated NetworkManager reload failure')
            if '-g' in args:
                field=args[args.index('-g')+1]
                text='802-3-ethernet' if field=='connection.type' else self.values[field]
            elif '--active' in args:text=UUID+':802-3-ethernet:eth0\nignored:vpn:tun0'
            elif 'modify' in args:
                pos=args.index('modify')+2
                self.values.update(zip(args[pos::2],args[pos+1::2]))
        elif '--sync' in args:
            if self.fail_sync:
                self.fail_sync=False;raise SetupError('simulated dispatcher error')
            self.values=dict(zip(FIELDS,['yes','','yes','']))
        return subprocess.CompletedProcess(args,code,text,'')


class SystemDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.run=FakeCommands();self.engine=SystemDeployment(self.root,self.run)
        self.plan={'installation_id':ID,'owner_uid':1000,'project':'/home/test/project','network':network(),
                   'adopt_existing':False,'missing_packages':[],'install_dependencies':False}
        p=self.engine.path(RESOLV);p.parent.mkdir(parents=True);p.write_text('nameserver 192.0.2.1\n')
        self.before=snapshot(p);self.values=copy.deepcopy(self.run.values)

    def tearDown(self):self.tmp.cleanup()

    def test_uninstall_leaves_provider_dns_and_working_os_resolver(self):
        self.engine.install(self.plan)
        self.assertTrue(self.engine.path(DISPATCHER).exists())
        self.assertEqual(self.engine.path(DISPATCHER).stat().st_mode&0o777,0o755)
        self.assertTrue(self.engine.path(RESOLV).is_symlink())
        self.assertTrue(self.run.service_active)
        # A profile written later by CLI must also be removed on uninstall.
        profile=self.engine.path(PROFILE);profile.parent.mkdir(parents=True,exist_ok=True)
        profile.write_text('# DNS Profile Manager: '+ID+'\n[Resolve]\nDNS=1.1.1.1\n')
        self.engine.uninstall(self.plan)
        self.assertEqual(os.readlink(self.engine.path(RESOLV)),RESOLVED_STUB)
        self.assertEqual(self.run.values,dict(zip(FIELDS,['no','','no',''])))
        self.assertTrue(self.run.service_active);self.assertTrue(self.run.service_enabled)
        for name in (DISPATCHER,ROOT_CONFIG,NM_CONFIG,JOURNAL,PROFILE):self.assertFalse(self.engine.path(name).exists())
        self.assertFalse(any('down' in call or 'NetworkManager' in call and 'restart' in call for call in self.run.calls))

    def test_uninstall_resumes_after_failure_during_system_cleanup(self):
        self.engine.install(self.plan)
        self.run.fail_general_reload=True
        with self.assertRaises(SetupError):self.engine.uninstall(self.plan)
        journal=self.engine.read()
        self.assertEqual(journal['phase'],'uninstalling')
        self.assertTrue(journal['uninstall_removed'])
        # Files already removed by the first attempt are recognized as our own work.
        result=self.engine.uninstall(self.plan)
        self.assertEqual(result['phase'],'uninstalled')
        self.assertEqual(self.run.values,dict(zip(FIELDS,['no','','no',''])))

    def test_failure_rolls_back(self):
        self.run.fail_sync=True
        with self.assertRaises(SetupError):self.engine.install(self.plan)
        self.assertEqual(snapshot(self.engine.path(RESOLV)),self.before)
        self.assertEqual(self.run.values,self.values)
        self.assertEqual(self.engine.read()['phase'],'rolled-back')
        self.assertFalse(self.engine.path(DISPATCHER).exists())

    def test_changed_system_file_is_not_deleted(self):
        self.engine.install(self.plan)
        self.engine.path(DISPATCHER).write_text('external replacement')
        with self.assertRaises(SetupError):self.engine.uninstall(self.plan)
        self.assertEqual(self.engine.path(DISPATCHER).read_text(),'external replacement')
        self.assertTrue(self.engine.path(JOURNAL).exists())

    def test_reinstall_preserves_original_snapshot(self):
        self.engine.install(self.plan);self.engine.install(self.plan);self.engine.rollback(self.plan)
        self.assertEqual(snapshot(self.engine.path(RESOLV)),self.before)
        self.assertEqual(self.run.values,self.values)

    def test_connection_changes_require_uninstall(self):
        self.engine.install(self.plan)
        changed=copy.deepcopy(self.plan);changed['network']['connections'][0]['interface']='eth1'
        with self.assertRaises(SetupError):self.engine.install(changed)

    def test_adopted_dispatcher_and_profiles_are_removed_on_uninstall(self):
        self.plan['adopt_existing']=True
        self.plan['network']['profile_file']=LEGACY_PROFILE
        old=self.engine.path(LEGACY_DISPATCHER);old.parent.mkdir(parents=True);old.write_text('# old dispatcher\n')
        old.chmod(0o755)
        profile=self.engine.path(LEGACY_PROFILE);profile.parent.mkdir(parents=True)
        profile.write_text('[Resolve]\nDNS=192.0.2.5#dns.example.org\nDNSOverTLS=yes\n')
        original=snapshot(profile)
        for name in LEGACY_DNS_PROFILES:self.engine.path(name).write_text('[Resolve]\nDNS=192.0.2.7\n')
        self.engine.install(self.plan)
        self.assertFalse(old.exists());self.assertEqual(snapshot(profile),original)
        profile.write_text('# DNS Profile Manager: '+ID+'\n[Resolve]\nDNS=192.0.2.6\n')
        self.engine.uninstall(self.plan)
        self.assertFalse(profile.exists());self.assertFalse(old.exists())
        for name in LEGACY_DNS_PROFILES:self.assertFalse(self.engine.path(name).exists())
        self.assertEqual(self.run.values,dict(zip(FIELDS,['no','','no',''])))

    def test_rollback_restores_adopted_setup_without_cleaning_it(self):
        self.plan['adopt_existing']=True
        self.plan['network']['profile_file']=LEGACY_PROFILE
        old=self.engine.path(LEGACY_DISPATCHER);old.parent.mkdir(parents=True);old.write_text('# previous dispatcher\n')
        profile=self.engine.path(LEGACY_PROFILE);profile.parent.mkdir(parents=True)
        profile.write_text('[Resolve]\nDNS=192.0.2.5\n')
        extra=self.engine.path(LEGACY_DNS_PROFILES[0]);extra.write_text('[Resolve]\nDNS=192.0.2.9\n')
        saved={p:snapshot(p) for p in (old,profile,extra,self.engine.path(RESOLV))}
        self.engine.install(self.plan);self.engine.rollback(self.plan)
        for path,before in saved.items():self.assertEqual(snapshot(path),before)
        self.assertEqual(self.run.values,self.values)
        self.assertFalse(self.run.service_active)

    def test_uninstall_clears_inactive_connection_without_reconnecting_it(self):
        secondary='00000000-0000-0000-0000-000000000003'
        self.plan['network']['connections'].append({'uuid':secondary,'type':'802-3-ethernet','interface':'','name':'Unplugged'})
        self.engine.install(self.plan);self.run.calls.clear()
        self.engine.uninstall(self.plan)
        modified=[row[3] for row in self.run.calls if row[:3]==['/usr/bin/nmcli','connection','modify']]
        self.assertEqual(set(modified),{UUID,secondary})
        reapplied=[row[-1] for row in self.run.calls if 'reapply' in row]
        self.assertEqual(reapplied,['eth0'])
        self.assertFalse(any('down' in row or 'up' in row for row in self.run.calls))

    def test_dependencies_require_explicit_consent(self):
        self.plan['missing_packages']=['curl']
        with self.assertRaises(SetupError):self.engine.install(self.plan)
        self.assertFalse(any('apt-get' in row[0] for row in self.run.calls))
        self.assertEqual(snapshot(self.engine.path(RESOLV)),self.before)

    def test_unmanaged_existing_dispatcher_is_not_overwritten(self):
        path=self.engine.path(DISPATCHER);path.parent.mkdir(parents=True);path.write_text('foreign')
        with self.assertRaises(SetupError):self.engine.install(self.plan)
        self.assertEqual(path.read_text(),'foreign')


class UserDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.home=self.root/'home';self.home.mkdir();self.project=self.root/'project';self.project.mkdir()
        self.deployment=UserDeployment(self.project,self.home)
        self.data=manager.validate_config(json.loads((manager.ROOT/'providers.default.json').read_text()))
        self.record={'installation_id':ID,'machine_id':manager.machine_identifier(),'state':'preparing'}

    def tearDown(self):self.tmp.cleanup()

    def test_user_install_and_remove_keep_project_config_and_unrelated_aliases(self):
        old=self.home/'.config/dns-manager';old.mkdir(parents=True)
        (old/'providers.json').write_text(json.dumps(self.data))
        self.deployment.aliases.write_text("alias editor='code'\n")
        self.deployment.localize(self.record)
        self.deployment.install_user(self.record,self.data)
        self.assertTrue(old.is_symlink())
        self.assertIn("alias editor='code'",self.deployment.aliases.read_text())
        self.deployment.aliases.write_text(self.deployment.aliases.read_text()+"alias later='echo later'\n")
        self.deployment.remove_user(self.record)
        self.assertEqual(self.deployment.aliases.read_text(),"alias editor='code'\nalias later='echo later'\n")
        self.assertTrue((self.project/'.local/config/providers.json').exists())
        self.assertFalse(old.is_symlink());self.assertTrue(self.project.exists())
        self.assertFalse((self.home/'.local/bin/dnsctl').is_symlink())

    def test_foreign_cli_file_is_preserved(self):
        binary=self.home/'.local/bin/dnsctl';binary.parent.mkdir(parents=True);binary.write_text('foreign')
        with self.assertRaises(SetupError):self.deployment.cli_targets(self.data)
        self.assertEqual(binary.read_text(),'foreign')

    def test_dry_run_does_not_create_local_files_or_call_root(self):
        plan={'network':network(),'missing_packages':[],'adopt_existing':False}
        options=SimpleNamespace(dry_run=True)
        with patch('os.geteuid',return_value=1000),patch.object(self.deployment,'make_plan',return_value=(plan,self.data)),patch.object(self.deployment,'system') as root,patch('sys.stdout',new=io.StringIO()):
            self.deployment.install(options)
        root.assert_not_called();self.assertFalse(self.deployment.local.exists())

    def test_foreign_machine_uninstall_does_not_touch_system(self):
        self.record.update(machine_id='another-machine',state='installed');self.deployment.save(self.record)
        with patch('os.geteuid',return_value=1000),patch.object(self.deployment,'system') as root,patch('sys.stdout',new=io.StringIO()):
            self.deployment.uninstall(SimpleNamespace(dry_run=False))
        root.assert_not_called()

    def test_apply_after_uninstall_is_blocked(self):
        self.deployment.save({**self.record,'state':'uninstalled'})
        with patch.object(manager,'LOCAL',self.deployment.local),patch.object(manager,'CONFIG',self.deployment.config/'providers.json'):
            with self.assertRaises(manager.ManagerError):manager.require_installation()


class DispatcherTests(unittest.TestCase):
    def test_single_nic_and_vpn_filter(self):
        data=network();commands=[]
        def run(args):
            commands.append(args)
            if '--active' in args:return UUID+':802-3-ethernet:eth0\n'+UUID+':vpn:tun0'
            return 'no' if '-g' in args and 'ignore-auto-dns' in args[args.index('-g')+1] else ''
        with tempfile.TemporaryDirectory() as temp:
            dispatcher.synchronize(data,run,Path(temp)/"absent-profile")
        self.assertFalse(any('modify' in row for row in commands))  # already DHCP
        self.assertFalse(any('tun0' in row for row in commands))

    def test_route_loss_is_recorded_and_recovery_flushes_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp)/'route';state.write_text('eth0|direct\n')
            def down(args):raise RuntimeError('no route')
            dispatcher.refresh_route(down,state);self.assertEqual(state.read_text(),'none\n')
            commands=[]
            def up(args):
                commands.append(args)
                return '[{"dev":"eth0"}]' if 'route' in args else ''
            dispatcher.refresh_route(up,state)
            self.assertTrue(any('flush-caches' in row for row in commands))

    def test_network_rejects_vpn_and_duplicate_uuid_case(self):
        data=network();data['connections'][0]['type']='vpn'
        with self.assertRaises(ValueError):dns_network.validate(data)
        data=network();item=copy.deepcopy(data['connections'][0]);data['connections'].append(item)
        with self.assertRaises(ValueError):dns_network.validate(data)


if __name__=='__main__':unittest.main()
