import pathlib
import tempfile
import unittest

BASE = pathlib.Path('/opt/unbound-webui')
REPO = pathlib.Path(__file__).resolve().parent


def main_with(fragment):
    return '''server:
    interface: 127.0.0.1
    port: 53535
    directory: "{1}"
    username: "unbound"
    chroot: ""
    pidfile: "{1}/unbound.pid"
    module-config: "validator iterator"
include: "{0}"
'''.format(fragment, fragment.parent)


class LocalZoneFilterProbe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/opt/unbound-webui')
        self.root = pathlib.Path(self.tmp.name)
        self.zone = self.root/'zone.conf'
        self.zone.write_text('server:\n    local-zone: "example.com." always_nxdomain\n    local-zone: "good.example.com." transparent\n')
        self.config = self.root/'unbound.conf'
        self.config.write_text(main_with(self.zone))
        self.proc = None

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        if self.proc and self.proc.stderr:
            self.proc.stderr.close()
        self.tmp.cleanup()

    def test_most_specific_allow_exception_does_not_expand_parent_zone(self):
        import subprocess, time, socket
        subprocess.run(['unbound-checkconf', str(self.config)], check=True, capture_output=True, text=True)
        self.proc = subprocess.Popen(['/usr/sbin/unbound', '-d', '-c', str(self.config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        for _ in range(30):
            try:
                with socket.create_connection(('127.0.0.1', 53535), timeout=.2): break
            except OSError: time.sleep(.1)
        def query(name):
            return subprocess.run(['dig','+time=1','+tries=1','@127.0.0.1','-p','53535',name,'A','+comments','+answer','+noquestion','+nostats'],capture_output=True,text=True).stdout
        ads = query('blocked.example.com')
        self.assertIn('status: NXDOMAIN', ads)
        unrelated = query('example.com.unrelated.net')
        self.assertNotIn('status: NXDOMAIN', unrelated)
        ok = query('www.good.example.com')
        self.assertNotIn('status: NXDOMAIN', ok)

if __name__ == '__main__': unittest.main()
