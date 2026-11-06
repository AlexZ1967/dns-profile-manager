"""Shell separation must preserve every unrelated byte of the shared aliases file."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dns_manager as m
import integrate


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.aliases = self.home/'.bash_aliases'
        self.config = self.home/'.config/dns-manager/providers.json'
        self.network = self.config.parent/'network.bash'
        self.patches = [patch.object(m,'ALIASES',self.aliases), patch.object(m,'CONFIG',self.config),
                        patch.object(m,'CACHE',self.home/'.cache/dns-manager'), patch.object(m,'NETWORK_CONFIG',self.network),
                        patch.object(Path,'home',return_value=self.home)]
        for p in self.patches:p.start()
        self.config.parent.mkdir(parents=True)
        self.config.write_text((m.ROOT/'providers.default.json').read_text())
        self.prefix = "# User shell customizations\nalias editor='code'\ncode() { printf '%s\\n' \"$@\"; }\n\n"
        self.suffix = "\n# Other commands after DNS\nalias notes='printf notes'\n"
        self.legacy = '''# DNS профили: Ethernet / Wi-Fi
DNS_ETH_UUID='00000000-0000-0000-0000-000000000001'
DNS_WIFI_UUID='00000000-0000-0000-0000-000000000002'
DNS_INTERFACES=('enp5s0' 'wlp4s0')
DNS_PROFILE_CONF='/etc/systemd/resolved.conf.d/90-dns-profile-manager.conf'
DNS_LEGACY_CONFS=(
    '/etc/systemd/resolved.conf.d/dns-ai.conf'
    '/etc/systemd/resolved.conf.d/dagami.conf'
)
_dns_active_connections() {
    :
}
_dns_switch() (
    :
)
# DNS Manager: shared provider configuration and generated CLI commands.
source ''' + str(self.config.parent/'commands.bash') + '\n'
        self.aliases.write_text(self.prefix+self.legacy+self.suffix)

    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()

    def migrate(self):
        with patch('sys.stdout',new=io.StringIO()):integrate.integrate()

    def test_dns_moves_to_project_hook_and_local_data_without_touching_other_commands(self):
        before=self.aliases.read_text()
        providers=json.loads(self.config.read_text())
        self.migrate()
        self.assertEqual(self.aliases.read_text(),self.prefix+integrate.hook_text()+self.suffix)
        self.assertNotIn('_dns_switch()',self.aliases.read_text())
        self.assertNotIn('DNS_ETH_UUID',self.aliases.read_text())
        settings=integrate.declarations(self.network.read_text())
        self.assertEqual(settings['DNS_ETH_UUID'],'00000000-0000-0000-0000-000000000001')
        self.assertEqual(settings['DNS_PROFILE_CONF'],'/etc/systemd/resolved.conf.d/90-dns-profile-manager.conf')
        self.assertEqual(json.loads(self.config.read_text()),providers)
        self.assertEqual(self.network.stat().st_mode & 0o777,0o600)
        backups=list((self.config.parent/'backups').glob('bash_aliases.*'))
        self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].read_text(),before)

    def test_repeated_integration_does_not_rewrite_aliases(self):
        self.migrate()
        text=self.aliases.read_text(); modified=self.aliases.stat().st_mtime_ns
        self.migrate()
        self.assertEqual(self.aliases.read_text(),text)
        self.assertEqual(self.aliases.stat().st_mtime_ns,modified)
        self.assertEqual(len(list((self.config.parent/'backups').glob('bash_aliases.*'))),1)

    def test_unknown_command_inside_legacy_block_is_not_deleted(self):
        before=self.aliases.read_text().replace('_dns_active_connections()', "alias unrelated='echo keep'\n_dns_active_connections()")
        self.aliases.write_text(before)
        with self.assertRaises(m.ManagerError):self.migrate()
        self.assertEqual(self.aliases.read_text(),before)
        self.assertFalse(self.network.exists())

    def test_existing_different_network_settings_stop_migration(self):
        settings=integrate.declarations(self.legacy)
        settings['DNS_ETH_UUID']='00000000-0000-0000-0000-000000000099'
        self.network.write_text(integrate.network_text(settings))
        before=self.aliases.read_text()
        with self.assertRaises(m.ManagerError):self.migrate()
        self.assertEqual(self.aliases.read_text(),before)
        self.assertIn('000000000099',self.network.read_text())

    def test_legacy_system_paths_are_allowlisted_before_migration(self):
        settings=integrate.declarations(self.legacy)
        settings['DNS_PROFILE_CONF']='/etc/sudoers'
        with self.assertRaises(m.ManagerError):integrate.validate_network_settings(settings)
        settings=integrate.declarations(self.legacy)
        settings['DNS_LEGACY_CONFS']=['/etc/shadow']
        with self.assertRaises(m.ManagerError):integrate.validate_network_settings(settings)

    def test_extra_command_in_hook_is_preserved_by_refusing_rewrite(self):
        self.migrate()
        before=self.aliases.read_text().replace('\n'+integrate.HOOK_END,'; echo keep\n'+integrate.HOOK_END,1)
        self.aliases.write_text(before)
        with self.assertRaises(m.ManagerError):self.migrate()
        self.assertEqual(self.aliases.read_text(),before)

    def test_runtime_does_not_execute_unrelated_shared_alias_commands(self):
        self.migrate()
        sentinel=self.home/'shared-file-was-executed'
        self.aliases.write_text('touch '+str(sentinel)+'\nexit 91\n')
        binary=self.home/'fakebin'; binary.mkdir()
        nmcli=binary/'nmcli'
        nmcli.write_text("#!/bin/sh\nif [ \"$1\" = -t ]; then\n printf '%s\\n' '00000000-0000-0000-0000-000000000001:enp5s0'\nelse\n printf 'Fixture\\nno\\nno\\n\\n\\n'\nfi\n")
        nmcli.chmod(0o755)
        import os
        with patch.dict(os.environ, {'PATH':str(binary)+':'+os.environ['PATH']}):
            connections=m.active_connections()
        self.assertEqual(len(connections),1)
        self.assertEqual(connections[0]['interface'],'enp5s0')
        self.assertFalse(sentinel.exists())


if __name__=='__main__':unittest.main()
