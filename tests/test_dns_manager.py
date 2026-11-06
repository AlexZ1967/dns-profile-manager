import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dns_manager as m


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.config = self.home/'config/providers.json'
        self.cache = self.home/'cache'
        self.patches = [patch.object(m,'CONFIG',self.config), patch.object(m,'CACHE',self.cache), patch.object(Path,'home',return_value=self.home)]
        for p in self.patches: p.start()
        self.data = json.loads((m.ROOT/'providers.default.json').read_text())
        m.save_config(self.data, install=False)

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.tmp.cleanup()

    def test_config_and_generated_commands_for_new_provider(self):
        p = copy.deepcopy(m.provider(self.data,'magic'))
        p.update(id='example',name='Example DNS',servers=['203.0.113.10'],tls_hostname='dns.example.org',command='dns-example-on',off_commands=['dns-example-off'])
        self.data['providers'].append(p)
        m.save_config(self.data)
        self.assertEqual(m.provider(m.load_config(),'example')['servers'],['203.0.113.10'])
        script=(self.config.parent/'commands.bash').read_text()
        self.assertIn('dns-example-on()',script)
        self.assertIn('apply example',script)
        self.assertTrue((self.home/'.local/bin/dns-example-on').is_symlink())
        p['command']='dns-renamed-on'
        m.save_config(self.data)
        self.assertFalse((self.home/'.local/bin/dns-example-on').exists())
        self.assertTrue((self.home/'.local/bin/dns-renamed-on').is_symlink())
        self.assertNotIn('203.0.113.10',script)  # Commands route by ID, never duplicate settings.

    def test_invalid_edit_is_atomic_and_rejects_injection(self):
        before=self.config.read_bytes()
        for field,value in [('command','dns-evil;id'),('servers',['1.1.1.1;id']),('tls_hostname','dns.example.org\nDNSOverTLS=no')]:
            data=copy.deepcopy(self.data); m.provider(data,'magic')[field]=value
            with self.assertRaises(m.ManagerError): m.save_config(data,install=False)
            self.assertEqual(before,self.config.read_bytes())

    def test_concurrent_config_edit_rejected(self):
        stale=m.fingerprint(self.data)
        data=copy.deepcopy(self.data); m.provider(data,'magic')['description']='Changed'
        m.save_config(data,install=False)
        with self.assertRaises(m.ManagerError): m.save_config(self.data,install=False,expected_hash=stale)

    def test_ipv6_and_tls_hostname_normalized_for_resolved(self):
        item=m.provider(self.data,'magic')
        item.update(servers=['2001:0DB8:0000:0000:0000:0000:0000:0001'],tls_hostname='API.MAGICDNS.RU',port=8853)
        m.validate_config(self.data)
        self.assertEqual(item['servers'],['2001:db8::1'])
        self.assertEqual(m.server_tokens(item),['[2001:db8::1]:8853#api.magicdns.ru'])

    def test_command_collision_not_overwritten(self):
        local=self.home/'.local/bin'; local.mkdir(parents=True)
        (local/'dns-magic-on').write_text('user command')
        with self.assertRaises(m.ManagerError): m.save_config(self.data)
        self.assertEqual((local/'dns-magic-on').read_text(),'user command')

    def test_current_uses_global_profile_not_fixed_interface(self):
        profile=self.home/'resolved.conf'; profile.write_text('[Resolve]\nDNS=45.88.163.92#api.magicdns.ru 109.120.177.170#api.magicdns.ru\nDNSOverTLS=yes\nDomains=~.\n')
        with patch.object(m,'PROFILE_FILE',profile), patch.object(m,'active_connections',return_value=[]), patch.object(m,'route_info',return_value={'interface':'wlp4s0'}), patch.object(m,'output',return_value='Global: 45.88.163.92#api.magicdns.ru 109.120.177.170#api.magicdns.ru'):
            state=m.current_state(self.data)
        self.assertEqual(state['id'],'magic'); self.assertTrue(state['config_matches']); self.assertTrue(state['effective_matches'])

    def test_dhcp_option_parser_excludes_local_address_mask_and_requested_flags(self):
        options='dhcp_server_identifier = 192.168.1.1 | domain_name_servers = 192.168.1.1 192.168.1.2 | ip_address = 192.168.1.73 | requested_domain_name_servers = 1 | subnet_mask = 255.255.255.0'
        with patch.object(m,'active_connections',return_value=[{'interface':'enp5s0'}]), patch.object(m,'run',return_value=subprocess.CompletedProcess([],0,options,'')):
            self.assertEqual(m.dhcp_servers(),['192.168.1.1','192.168.1.2'])

    def test_changed_active_config_requires_reapply(self):
        profile=self.home/'resolved.conf'; profile.write_text('[Resolve]\nDNS=45.88.163.92#api.magicdns.ru\nDNSOverTLS=yes\n')
        with patch.object(m,'PROFILE_FILE',profile), patch.object(m,'active_connections',return_value=[]), patch.object(m,'route_info',return_value={}), patch.object(m,'output',return_value='Global: 45.88.163.92#api.magicdns.ru'):
            state=m.current_state(self.data)
        self.assertEqual(state['id'],'magic'); self.assertFalse(state['config_matches'])

    def test_dot_verifies_certificate_and_https_uses_provider_answer(self):
        p=m.provider(self.data,'magic')
        dns=subprocess.CompletedProcess([],0,json.dumps({'RCODE':0,'answerRRs':[{'TYPE':1,'rdataA':'203.0.113.7'}]}),'')
        with patch.object(m,'run',return_value=dns) as run:
            answer=m.dns_query(p,p['servers'][0],'github.com',2)
            args=run.call_args.args[0]
            self.assertIn('+tls-ca',args); self.assertIn('+tls-hostname=api.magicdns.ru',args); self.assertIn('+tls-sni=api.magicdns.ru',args)
        self.assertTrue(answer['ok'])
        with patch.object(m,'run',return_value=subprocess.CompletedProcess([],0,json.dumps({'http_code':403,'time_connect':0.1,'time_appconnect':0.2,'time_starttransfer':0.3,'ssl_verify_result':0}),'')) as run:
            result=m.https_query('github.com','203.0.113.7',5)
            args=run.call_args.args[0]
            self.assertIn('github.com:443:203.0.113.7',args); self.assertIn('--resolve',args); self.assertIn('--noproxy',args)
            self.assertNotIn('-k',args)
        self.assertFalse(result['ok']); self.assertIn('доступ ограничен',result['detail'])

    def _check(self, dns_ok=True, https_ok=True, one_bad_server=False):
        def query(p,server,domain,timeout):
            good=dns_ok and not (one_bad_server and server==p['servers'][-1])
            return {'server':server,'domain':domain,'ok':good,'addresses':['203.0.113.7'] if good else [],'detail':'timeout' if not good else '', 'ms':2}
        def https(domain,ip,timeout): return {'domain':domain,'address':ip,'ok':https_ok,'code':200 if https_ok else 403,'detail':'HTTP 200' if https_ok else 'HTTP 403'}
        with patch.object(m,'network_fingerprint',return_value='network'),patch.object(m,'route_info',return_value={'interface':'test0','gateway':'192.0.2.1'}),patch.object(m,'dns_query',side_effect=query),patch.object(m,'https_query',side_effect=https),patch.object(m.shutil,'which',return_value='/usr/bin/tool'):
            return m.check_provider('magic')

    def test_health_green_yellow_red_are_distinct(self):
        self.assertEqual(self._check()['state'],'green')
        partial=self._check(https_ok=False); self.assertEqual(partial['state'],'yellow'); self.assertTrue(partial['issues'])
        self.assertEqual(self._check(one_bad_server=True)['state'],'yellow')
        self.assertEqual(self._check(dns_ok=False)['state'],'red')

    def test_route_changes_and_config_edits_invalidate_badge(self):
        self._check()
        self.assertIn('magic',m.health_results(self.data,'network'))
        self.assertNotIn('magic',m.health_results(self.data,'other-network'))
        changed=copy.deepcopy(self.data); m.provider(changed,'magic')['servers']=['203.0.113.8']
        self.assertNotIn('magic',m.health_results(changed,'network'))

    def test_simultaneous_apply_is_rejected_before_any_command(self):
        with m.lock(self.cache/'operation.lock'):
            with patch.object(m.subprocess,'Popen') as popen:
                with self.assertRaises(m.ManagerError): m.apply_profile('magic')
                popen.assert_not_called()

    def test_apply_uses_current_config_and_existing_network_functions(self):
        p=m.provider(self.data,'magic'); p['servers']=['203.0.113.19']
        m.save_config(self.data,install=False)
        fake=unittest.mock.Mock(); fake.stdout=iter(['done\n']); fake.wait.return_value=0
        with patch.object(m.subprocess,'Popen',return_value=fake) as popen,patch.object(m,'current_state',return_value={'id':'magic','config_matches':True,'effective_matches':True}):
            m.apply_profile('magic',lambda line:None,gui=True)
            args=popen.call_args.args[0]
            self.assertIn('203.0.113.19#api.magicdns.ru',args)
            self.assertIn('_dns_switch',args[2])
            self.assertEqual(popen.call_args.kwargs['env']['DNS_MANAGER_GUI'],'1')


@unittest.skipUnless(m.NETWORK_BACKEND.exists(), 'Project network module not found')
class ExistingNetworkHelperTests(unittest.TestCase):
    def settings(self, root):
        path=root/'network.bash'
        path.write_text("DNS_ETH_UUID='00000000-0000-0000-0000-000000000001'\nDNS_WIFI_UUID='00000000-0000-0000-0000-000000000002'\nDNS_INTERFACES=(enp5s0 wlp4s0)\nDNS_PROFILE_CONF='"+str(root/'profile.conf')+"'\nDNS_LEGACY_CONFS=('"+str(root/'legacy')+"')\n")
        return path
    def test_only_known_active_connections_reapplied(self):
        # Execute the real Bash helper with fake nmcli; no sudo or network changes.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); log=root/'calls.jsonl'; cli=root/'nmcli'
            eth='00000000-0000-0000-0000-000000000001'; wifi='00000000-0000-0000-0000-000000000002'
            cli.write_text('''#!/usr/bin/python3
import os,sys,json
from pathlib import Path
args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps(args)+'\\n')
if args==['-t','-f','UUID,DEVICE','connection','show','--active']:
 print(os.environ['ACTIVE'])
'''); cli.chmod(0o755)
            for active,expected in [(eth+':enp5s0',['enp5s0']),(wifi+':wlp4s0',['wlp4s0']),(eth+':enp5s0\n'+wifi+':wlp4s0',['enp5s0','wlp4s0'])]:
                log.write_text('')
                env={**os.environ,'DNS_MANAGER_NETWORK_CONFIG':str(self.settings(root)),'PATH':str(root)+':'+os.environ['PATH'],'CALLS':str(log),'ACTIVE':active+'\nunknown-vpn:tun0\nother-uuid:enp6s0'}
                result=subprocess.run(['bash','-c','source "$1"; DNS_ETH_UUID="$2"; DNS_WIFI_UUID="$3"; _dns_nm_configure yes','_',str(m.NETWORK_BACKEND),eth,wifi],env=env,capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                calls=[json.loads(l) for l in log.read_text().splitlines()]
                reapplied=[c[2] for c in calls if c[:2]==['device','reapply']]
                self.assertEqual(reapplied,expected)
                self.assertFalse(any('down' in c or 'up' in c or 'route-metric' in ' '.join(c) for c in calls))
                modified=[c[2] for c in calls if c[:2]==['connection','modify']]
                self.assertEqual(set(modified),{eth if dev=='enp5s0' else wifi for dev in expected})


    def test_real_switch_helper_with_mock_system_commands_and_atomic_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binpath=root/'bin'; binpath.mkdir(); calls=root/'calls.jsonl'
            eth='00000000-0000-0000-0000-000000000001'
            dispatcher=root/'dispatcher.lock'  # First use must create the shared lock.
            aliases=root/'aliases'; aliases.write_text(m.NETWORK_BACKEND.read_text().replace('/run/lock/nm-dns-primary-route.lock',str(dispatcher)))
            command_code = r"""#!/usr/bin/python3
import os,sys,json
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps([name,*args])+'\n')
if name=='nmcli' and args==['-t','-f','UUID,DEVICE','connection','show','--active']:
 print(os.environ['ETH']+':enp5s0')
if name=='nmcli' and args==['-t','--escape','no','-f','UUID,TYPE,DEVICE','connection','show','--active']:
 print(os.environ['ETH']+':802-3-ethernet:enp5s0')
if name=='sudo':
 assert args[0]=='/usr/bin/bash',args
 if os.environ.get('AUTH_FAIL')=='1':sys.exit(1)
 # Execute without elevation; every system-changing command is a fixture below.
 os.execv(args[0],args)
if name=='systemctl':
 assert args==['restart','systemd-resolved'];sys.exit(0)
if name=='resolvectl':sys.exit(0)
if name in ['mkdir','chmod','mv','rm']:
 for arg in args:
  if arg.startswith('/'):
   assert arg == os.environ['TEST_ROOT'] or arg.startswith(os.environ['TEST_ROOT']+'/'),arg
 os.execv('/usr/bin/'+name,[name,*args])
"""
            for name in ['nmcli','sudo','resolvectl','mkdir','chmod','mv','rm','systemctl']:
                path=binpath/name; path.write_text(command_code); path.chmod(0o755)
            env={**os.environ,'DNS_MANAGER_NETWORK_CONFIG':str(self.settings(root)),'PATH':str(binpath)+':'+os.environ['PATH'],'CALLS':str(calls),'TEST_ROOT':tmp,'ETH':eth}
            prefix='source "$1"; DNS_ETH_UUID="$2"; DNS_PROFILE_CONF="$3"; DNS_LEGACY_CONFS=("$4/legacy"); '
            args=['_',str(aliases),eth,str(root/'profile.conf'),tmp]
            result=subprocess.run(['bash','-c',prefix+'_dns_switch "Fixture" "203.0.113.10#dns.example.org" yes',*args],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            content=(root/'profile.conf').read_text()
            self.assertIn('DNS=203.0.113.10#dns.example.org',content)
            self.assertIn('DNSOverTLS=yes',content)
            self.assertIn('Domains=~.',content)
            self.assertFalse(list(root.glob('profile.conf.*')))
            result=subprocess.run(['bash','-c',prefix+'_dns_provider_apply',*args],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse((root/'profile.conf').exists())
            self.assertTrue(dispatcher.is_file())
            self.assertEqual(dispatcher.stat().st_mode & 0o777,0o644)
            entries=[json.loads(line) for line in calls.read_text().splitlines()]
            self.assertFalse(any('NetworkManager' in e or 'down' in e or 'up' in e for e in entries))
            changes=[e for e in entries if e[:3]==['nmcli','connection','modify']]
            self.assertEqual([e[5] for e in changes],['yes','no'])
            authorizations=[e for e in entries if e[0]=='sudo']
            self.assertEqual(len(authorizations),2)  # One each for manual DNS and DHCP.
            self.assertTrue(all(e[1]=='/usr/bin/bash' for e in authorizations))
            self.assertEqual(sum(e[:2]==['systemctl','restart'] for e in entries),2)
            # Cancelling the only authorization must prevent all system mutations.
            calls.write_text('')
            result=subprocess.run(['bash','-c',prefix+'_dns_switch "Fixture" "203.0.113.10#dns.example.org" yes',*args],env={**env,'AUTH_FAIL':'1'},capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((root/'profile.conf').exists())
            cancelled=[json.loads(line) for line in calls.read_text().splitlines()]
            self.assertEqual(sum(e[0]=='sudo' for e in cancelled),1)
            self.assertFalse(any(e[0] in ('mkdir','chmod','mv','rm','systemctl') or e[:3]==['nmcli','connection','modify'] for e in cancelled))
            # New installations use a variable-length physical connection array.
            # Literal shell syntax in a display name must never become executable.
            calls.write_text('')
            malicious_name='Fixture $(touch '+str(root/'unexpected-command')+')'
            command=prefix+'DNS_CONNECTIONS=("$2||802-3-ethernet"); _dns_switch "$5" "203.0.113.10#dns.example.org" yes'
            result=subprocess.run(['bash','-c',command,*args,malicious_name],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse((root/'unexpected-command').exists())
            self.assertIn('DNS=203.0.113.10#dns.example.org',(root/'profile.conf').read_text())
            serialized=[json.loads(line) for line in calls.read_text().splitlines()]
            self.assertEqual(sum(e[0]=='sudo' for e in serialized),1)

    def test_failed_networkmanager_apply_restores_previous_profile(self):
        # A failed nmcli connection modify triggers the rollback: previous
        # resolved profile text and per-connection DNS fields are restored.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binpath=root/'bin'; binpath.mkdir(); calls=root/'calls.jsonl'
            eth='00000000-0000-0000-0000-000000000001'
            dispatcher=root/'dispatcher.lock'; dispatcher.touch()
            profile=root/'profile.conf'; profile.write_text('# Manual DNS=192.0.2.9\n')
            legacy=root/'legacy'; legacy.write_text('legacy')
            aliases=root/'aliases'; aliases.write_text(m.NETWORK_BACKEND.read_text().replace('/run/lock/nm-dns-primary-route.lock',str(dispatcher)))
            command_code = r"""#!/usr/bin/python3
import os,sys,json
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps([name,*args])+'\n')
if name=='nmcli' and args==['-t','-f','UUID,DEVICE','connection','show','--active']:
    print(os.environ['ETH']+':enp5s0')
if name=='nmcli' and args==['-t','--escape','no','-f','UUID,TYPE,DEVICE','connection','show','--active']:
    print(os.environ['ETH']+':802-3-ethernet:enp5s0')
if name=='nmcli' and args[:5]==['-t','--escape','no','-g','ipv4.ignore-auto-dns,ipv4.dns,ipv6.ignore-auto-dns,ipv6.dns']:
    print('no\n192.0.2.1\nno\n--')
if name=='nmcli' and 'modify' in args and 'yes' in args and os.environ.get('MODIFY_FAIL')=='1':
    print('Fixture: connection modify failed',file=sys.stderr);sys.exit(2)
if name=='sudo':
    assert args[0]=='/usr/bin/bash',args
    # Execute without elevation; every system-changing command is a fixture below.
    os.execv(args[0],args)
if name=='systemctl':
    assert args==['restart','systemd-resolved'];sys.exit(0)
if name=='resolvectl':sys.exit(0)
if name in ['mkdir','chmod','mv','rm']:
    for arg in args:
        if arg.startswith('/'):
            assert arg == os.environ['TEST_ROOT'] or arg.startswith(os.environ['TEST_ROOT']+'/'),arg
    os.execv('/usr/bin/'+name,[name,*args])
"""
            for name in ['nmcli','sudo','resolvectl','mkdir','chmod','mv','rm','systemctl']:
                path=binpath/name; path.write_text(command_code); path.chmod(0o755)
            env={**os.environ,'DNS_MANAGER_NETWORK_CONFIG':str(self.settings(root)),'PATH':str(binpath)+':'+os.environ['PATH'],'CALLS':str(calls),'TEST_ROOT':str(root),'ETH':eth,'MODIFY_FAIL':'1'}
            prefix='source "$1"; DNS_ETH_UUID="$2"; DNS_PROFILE_CONF="$3"; DNS_LEGACY_CONFS=("$4"); '
            args=['_',str(aliases),eth,str(profile),str(legacy)]
            result=subprocess.run(['bash','-c',prefix+'_dns_switch "Fixture" "203.0.113.10#dns.example.org" yes',*args],env=env,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            # The previous profile text is restored verbatim; no staged leftovers.
            self.assertEqual(profile.read_text(),'# Manual DNS=192.0.2.9\n')
            self.assertFalse(list(root.glob('profile.conf.*')))
            # Restored per-connection fields use the captured values (ignore-auto-dns no).
            entries=[json.loads(line) for line in calls.read_text().splitlines()]
            restores=[e for e in entries if e[:3]==['nmcli','connection','modify'] and 'yes' not in e]
            self.assertEqual(len(restores),1)
            self.assertIn('no',restores[0])
            self.assertIn('192.0.2.1',restores[0])
            self.assertNotIn('--',restores[0])
            self.assertEqual(sum(e[:3]==['nmcli','device','reapply'] and e[3]=='enp5s0' for e in entries),1)
            # Rollback restarts resolved so the restored configuration takes effect.
            self.assertEqual(sum(e[:2]==['systemctl','restart'] for e in entries),1)
            # Known limitation: legacy confs removed during the failed run are not restored.
            self.assertFalse(legacy.exists())


if __name__=='__main__': unittest.main()
