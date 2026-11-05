"""Transport and reporting regression cases. Every network command is mocked."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dns_diagnostics as d
import dns_manager as m


class HttpsProbeTests(unittest.TestCase):
    def response(self, code=200, exitcode=0, headers='', body='', timings=None):
        metadata = {'http_code': code, 'time_connect': 0.030, 'time_appconnect': 0.090,
                    'time_starttransfer': 0.150, 'ssl_verify_result': 0, 'remote_ip': '203.0.113.20'}
        metadata.update(timings or {})
        def run(args, timeout):
            Path(args[args.index('--dump-header') + 1]).write_text('HTTP/2 ' + str(code) + '\r\n' + headers)
            Path(args[args.index('--output') + 1]).write_text(body)
            return subprocess.CompletedProcess(args, exitcode, json.dumps(metadata), 'fixture error' if exitcode else '')
        return run

    def test_real_stages_and_secure_pinned_curl_arguments(self):
        with patch.object(m, 'run', side_effect=self.response()) as run:
            result = m.https_query('claude.ai', '203.0.113.20', 8)
        self.assertTrue(result['ok'])
        self.assertEqual(result['timings']['tcp_ms'], 30.0)
        self.assertEqual(result['timings']['tls_ms'], 60.0)
        self.assertEqual(result['timings']['ttfb_ms'], 150.0)
        args = run.call_args.args[0]
        self.assertEqual(args[:2], ['curl', '--disable'])
        self.assertIn('claude.ai:443:203.0.113.20', args)
        self.assertEqual(args[args.index('--proxy')+1], '')
        self.assertNotIn('-k', args)
        self.assertNotIn('-L', args)

    def test_http_403_is_not_tls_failure_or_success(self):
        with patch.object(m, 'run', side_effect=self.response(code=403)):
            result = m.https_query('claude.ai', '203.0.113.20', 8)
        self.assertFalse(result['ok'])
        self.assertTrue(result['tls_ok'])
        self.assertIn('доступ ограничен', result['detail'])

    def test_cloudflare_challenge_even_with_http_200_is_partial(self):
        with patch.object(m, 'run', side_effect=self.response(headers='cf-mitigated: challenge\r\n')):
            result = m.https_query('www.perplexity.ai', '203.0.113.20', 8)
        self.assertFalse(result['ok'])
        self.assertTrue(result['challenge'])
        self.assertIn('CAPTCHA', result['detail'])

    def test_body_size_limit_preserves_valid_https_result(self):
        with patch.object(m, 'run', side_effect=self.response(exitcode=63)):
            result = m.https_query('claude.ai', '203.0.113.20', 8)
        self.assertTrue(result['ok'])
        self.assertTrue(result['body_truncated'])

    def test_certificate_failure_has_tls_stage(self):
        with patch.object(m, 'run', side_effect=self.response(code=0, exitcode=60, timings={'time_appconnect': 0, 'ssl_verify_result':20})):
            result = m.https_query('claude.ai', '203.0.113.20', 8)
        self.assertFalse(result['ok'])
        self.assertFalse(result['tls_ok'])
        self.assertTrue(result['tcp_ok'])
        self.assertIn('TLS:', result['detail'])

    def test_tcp_timeout_has_tcp_stage(self):
        with patch.object(m, 'run', side_effect=self.response(code=0, exitcode=28, timings={'time_connect':0, 'time_appconnect':0})):
            result = m.https_query('claude.ai', '203.0.113.20', 8)
        self.assertFalse(result['tcp_ok'])
        self.assertIn('TCP:', result['detail'])

    def test_region_error_in_json_is_not_success(self):
        with patch.object(m, 'run', side_effect=self.response(headers='content-type: application/json\r\n', body='{"error":"unsupported_country"}')):
            result = m.https_query('claude.ai', '203.0.113.20', 8)
        self.assertFalse(result['ok'])
        self.assertTrue(result['regional_restriction'])


class RedirectTests(unittest.TestCase):
    def hop(self, host, ip, code=200, location='', path='/'):
        return {'domain':host,'address':ip,'url':'https://'+host+path,'code':code,'ok':code==200,
                'location':location,'detail':f'HTTP {code}','transport_ok':True,'tcp_ok':True,'tls_ok':True,
                'timings':{'tcp_ms':10,'tls_ms':20,'ttfb_ms':35,'total_ms':40}}

    def test_cross_host_redirect_is_resolved_using_same_provider(self):
        calls=[]; resolutions=[]
        def probe(host,ip,timeout,path='/'):
            calls.append((host,ip,path))
            return self.hop(host,ip,302,'https://login.example.org/start') if len(calls)==1 else self.hop(host,ip,path=path)
        def resolve(host,remaining):
            resolutions.append(host)
            return [{'server':'192.0.2.53','domain':host,'ok':True,'addresses':['203.0.113.21'],'detail':'','ms':4}]
        result=d.follow_https('claude.ai','203.0.113.20',8,probe,resolve)
        self.assertTrue(result['ok'])
        self.assertEqual(resolutions,['login.example.org'])
        self.assertEqual(calls[1],('login.example.org','203.0.113.21','/start'))
        self.assertEqual(result['redirects'],1)
        self.assertEqual(result['timings']['tcp_ms'],20)

    def test_no_system_dns_fallback_when_redirect_dns_fails(self):
        calls=[]
        def probe(host,ip,timeout,path='/'):
            calls.append(host)
            return self.hop(host,ip,302,'https://other.example.org/')
        result=d.follow_https('claude.ai','203.0.113.20',8,probe,lambda *_:[])
        self.assertFalse(result['ok'])
        self.assertEqual(calls,['claude.ai'])
        self.assertIn('DNS перенаправления',result['detail'])

    def test_http_downgrade_not_followed(self):
        with patch.object(d,'probe_https') as unused:
            result=d.follow_https('claude.ai','203.0.113.20',8,
                lambda *args:self.hop('claude.ai','203.0.113.20',302,'http://claude.ai/'),lambda *_:[])
        self.assertFalse(result['ok'])
        self.assertEqual(len(result['hops']),1)
        self.assertIn('HTTP',result['detail'])
        unused.assert_not_called()

    def test_redirect_loop_is_not_green(self):
        result=d.follow_https('claude.ai','203.0.113.20',8,
            lambda *args:self.hop('claude.ai','203.0.113.20',302,'https://claude.ai/'),lambda *_:[])
        self.assertFalse(result['ok'])
        self.assertIn('цикл',result['detail'])

    def test_302_without_location_is_incomplete(self):
        result=d.follow_https('claude.ai','203.0.113.20',8,
            lambda *args:self.hop('claude.ai','203.0.113.20',302),lambda *_:[])
        self.assertFalse(result['ok'])
        self.assertIn('нет адреса',result['detail'])


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.data=json.loads((m.ROOT/'providers.default.json').read_text())

    def test_catalog_has_six_ai_services_and_github_control(self):
        catalog=m.diagnostic_services(self.data)
        self.assertEqual(sum(s['role']=='ai' for s in catalog),6)
        self.assertTrue(any(s['name']=='Claude' for s in catalog))
        self.assertTrue(any(s['name']=='Perplexity' for s in catalog))
        self.assertEqual(next(s for s in catalog if s['id']=='github')['role'],'control')

    def test_legacy_config_upgrade_preserves_providers_and_custom_targets(self):
        old=copy.deepcopy(self.data)
        old.pop('test_services')
        old['test_domains']=['chatgpt.com','custom.example.org']
        upgraded=m.upgraded_diagnostics_config(old)
        self.assertEqual(upgraded['providers'],old['providers'])
        self.assertTrue(any(s['host']=='custom.example.org' for s in upgraded['test_services']))
        self.assertNotIn('test_domains',upgraded)
        self.assertEqual(old['test_domains'],['chatgpt.com','custom.example.org'])

    def test_duplicate_service_host_is_rejected(self):
        self.data['test_services'].append({'id':'other','name':'Other','host':'CLAUDE.AI','role':'ai'})
        with self.assertRaises(m.ManagerError):m.validate_config(self.data)

    def test_service_change_invalidates_diagnostic_signature(self):
        before=m.diagnostics_signature(self.data)
        self.data['test_services'][0]['host']='other.example.org'
        self.assertNotEqual(before,m.diagnostics_signature(self.data))

    def test_failed_dns_is_separate_from_https_403(self):
        service=d.DEFAULT_SERVICES[0]
        dns=[{'domain':service['host'],'server':'192.0.2.53','ok':True,'addresses':['203.0.113.20'],'ms':5,'detail':''}]
        restricted=[{'domain':service['host'],'code':403,'ok':False,'detail':'HTTP 403','tcp_ok':True,'tls_ok':True}]
        result=d.summarize_service(service,dns,restricted)
        self.assertEqual(result['state'],'yellow')
        self.assertTrue(result['tls_ok'])
        dns[0].update(ok=False,addresses=[],detail='timeout')
        self.assertEqual(d.summarize_service(service,dns,[])['state'],'red')


if __name__=='__main__':unittest.main()
