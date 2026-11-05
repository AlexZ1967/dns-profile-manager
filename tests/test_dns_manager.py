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
        with patch.object(m,'run',return_value=subprocess.CompletedProcess([],0,'403\t0.1\t0.2','')) as run:
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
        with patch.object(m,'network_fingerprint',return_value='network'),patch.object(m,'dns_query',side_effect=query),patch.object(m,'https_query',side_effect=https),patch.object(m.shutil,'which',return_value='/usr/bin/tool'):
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


@unittest.skipUnless(m.ALIASES.exists() and '_dns_nm_configure()' in m.ALIASES.read_text(), 'Existing network helpers not integrated')
class ExistingNetworkHelperTests(unittest.TestCase):
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
                env={**os.environ,'PATH':str(root)+':'+os.environ['PATH'],'CALLS':str(log),'ACTIVE':active+'\nunknown-vpn:tun0\nother-uuid:enp6s0'}
                result=subprocess.run(['bash','-c','source "$1"; DNS_ETH_UUID="$2"; DNS_WIFI_UUID="$3"; _dns_nm_configure yes','_',str(m.ALIASES),eth,wifi],env=env,capture_output=True,text=True)
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
            dispatcher=root/'dispatcher.lock'; dispatcher.touch()
            aliases=root/'aliases'; aliases.write_text(m.ALIASES.read_text().replace('/run/lock/nm-dns-primary-route.lock',str(dispatcher)))
            command_code = r"""#!/usr/bin/python3
import os,sys,json
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps([name,*args])+'\n')
if name=='nmcli' and args==['-t','-f','UUID,DEVICE','connection','show','--active']:
 print(os.environ['ETH']+':enp5s0')
if name=='sudo':
 if args==['-v']:sys.exit(0)
 if args[:2]==['mkdir','-p']:
  assert args[2]=='/etc/systemd/resolved.conf.d';sys.exit(0)
 if args[0]=='systemctl':
  assert args==['systemctl','restart','systemd-resolved'];sys.exit(0)
 if args[0]=='resolvectl':
  assert args==['resolvectl','flush-caches'];sys.exit(0)
 assert args[0] in ['tee','chmod','mv','rm']
 for arg in args[1:]:
  if arg.startswith('/'):
   assert arg.startswith(os.environ['TEST_ROOT']+'/'),arg
 os.execv('/usr/bin/'+args[0],args)
"""
            for name in ['nmcli','sudo','resolvectl']:
                path=binpath/name; path.write_text(command_code); path.chmod(0o755)
            env={**os.environ,'PATH':str(binpath)+':'+os.environ['PATH'],'CALLS':str(calls),'TEST_ROOT':tmp,'ETH':eth}
            prefix='source "$1"; DNS_ETH_UUID="$2"; DNS_PROFILE_CONF="$3"; DNS_LEGACY_CONFS=("$4/legacy"); '
            args=['_',str(aliases),eth,str(root/'profile.conf'),tmp]
            result=subprocess.run(['bash','-c',prefix+'_dns_switch "Fixture" "203.0.113.10#dns.example.org" yes',*args],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            content=(root/'profile.conf').read_text()
            self.assertIn('DNS=203.0.113.10#dns.example.org',content)
            self.assertIn('DNSOverTLS=yes',content)
            self.assertIn('Domains=~.',content)
            self.assertFalse((root/'profile.conf.new').exists())
            result=subprocess.run(['bash','-c',prefix+'_dns_provider_apply',*args],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse((root/'profile.conf').exists())
            entries=[json.loads(line) for line in calls.read_text().splitlines()]
            self.assertFalse(any('NetworkManager' in e or 'down' in e or 'up' in e for e in entries))
            changes=[e for e in entries if e[:3]==['nmcli','connection','modify']]
            self.assertEqual([e[5] for e in changes],['yes','no'])


if __name__=='__main__': unittest.main()
