"""Regression: dialog processes must not put menu frames in shell scrollback."""
import fcntl
import os
from pathlib import Path
import pty
import select
import shutil
import struct
import subprocess
import termios
import time
import tempfile
import unittest


@unittest.skipUnless(shutil.which('dialog') and Path('/usr/bin/tic').exists(), 'dialog/terminfo not installed')
class TerminalTests(unittest.TestCase):
    def test_alternate_screen_owned_once_and_restored_on_escape(self):
        master,slave=pty.openpty()
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',30,100,0,0))
        root=Path(__file__).resolve().parents[1]
        sandbox=tempfile.TemporaryDirectory()
        temp=Path(sandbox.name)
        (temp/'providers.json').write_text((root/'providers.default.json').read_text())
        (temp/'aliases').write_text('_dns_active_connections() { :; }\n')
        for name,text in [('ip', '[]'), ('resolvectl', 'Global:')]:
            command=temp/name; command.write_text('#!/bin/sh\nprintf \'%s\\n\' '+repr(text)+'\n'); command.chmod(0o755)
        child_env={**os.environ,'TERM':'xterm-256color','DNS_MANAGER_CONFIG':str(temp/'providers.json'),'DNS_MANAGER_CACHE':str(temp/'cache'),'DNS_ALIASES_FILE':str(temp/'aliases'),'PATH':str(temp)+':'+os.environ['PATH']}
        process=subprocess.Popen([str(root/'dns-menu')],stdin=slave,stdout=slave,stderr=slave,env=child_env)
        os.close(slave)
        data=bytearray(); sent=False; deadline=time.monotonic()+15
        try:
            while time.monotonic()<deadline:
                ready,_,_=select.select([master],[],[],0.2)
                if ready:
                    try:chunk=os.read(master,65536)
                    except OSError:break
                    if not chunk:break
                    data.extend(chunk)
                    if not sent and b'DNS Profile Manager' in data:
                        os.write(master,b'\x1b\x1b'); sent=True
                if process.poll() is not None:break
            process.wait(timeout=3)
            self.assertTrue(sent,bytes(data).decode(errors='replace'))
            self.assertEqual(process.returncode,0)
            # Drain endwin/tput output after process exit.
            while select.select([master],[],[],0)[0]:
                try:
                    chunk=os.read(master,65536)
                    if not chunk:break
                    data.extend(chunk)
                except OSError:break
            self.assertEqual(data.count(b'\x1b[?1049h'),1)
            self.assertEqual(data.count(b'\x1b[?1049l'),1)
        finally:
            if process.poll() is None:process.kill(); process.wait()
            os.close(master)
            sandbox.cleanup()


if __name__=='__main__':unittest.main()
