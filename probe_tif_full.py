import pathlib
import resource
import shutil
import socket
import subprocess
import tempfile
import time
import filters
filters.MAX_BYTES = 64 * 1024 * 1024

start = time.monotonic()
raw = filters.download_list('https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt')
print('download_s', round(time.monotonic()-start, 2), 'bytes', len(raw), flush=True)
start = time.monotonic()
parsed = filters.parse_list(raw, max_domains=3_000_000)
print('parse_s', round(time.monotonic()-start, 2), 'domains', len(parsed['domains']),
      'unsupported', parsed['unsupported'], 'python_peak_rss_mib',
      round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024, 1), flush=True)
config, count = filters.render_config(parsed['domains'], [], max_domains=3_000_000)
print('rendered rules', count, 'config_bytes', len(config), flush=True)
with tempfile.TemporaryDirectory(prefix='tif-full-probe-', dir='/opt/unbound-webui') as td:
    root=pathlib.Path(td); (root/'zones').mkdir(); (root/'zones'/'filters.conf').write_text(config)
    main=root/'unbound.conf'
    main.write_text('''server:
    interface: 127.0.0.1
    port: 53536
    username: "unbound"
    directory: "{root}"
    chroot: ""
    pidfile: "{root}/unbound.pid"
    module-config: "validator iterator"
include: "{root}/zones/filters.conf"
'''.format(root=root))
    subprocess.run(['unbound-checkconf',str(main)],check=True,capture_output=True,text=True)
    started=time.monotonic()
    probe_name = parsed['domains'][0]
    proc=subprocess.Popen(['/usr/sbin/unbound','-d','-c',str(main)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    ready=False
    last_query = ''
    for _ in range(900):
        if proc.poll() is not None:
            raise RuntimeError((proc.stderr.read() if proc.stderr else '')[:4000])
        try:
            last_query=subprocess.run(['dig','+time=1','+tries=1','@127.0.0.1','-p','53536',probe_name,'A','+comments','+noquestion','+nostats'],capture_output=True,text=True).stdout
            if 'status: NXDOMAIN' in last_query:
                ready=True;break
        except OSError:
            pass
        time.sleep(.1)
    if not ready: raise RuntimeError('Resolver did not answer an actual filtered query within 90 s: '+last_query[:500])
    startup=time.monotonic()-started
    rss=subprocess.check_output(['ps','-o','rss=','-p',str(proc.pid)],text=True).strip()
    print('isolated_unbound_startup_s',round(startup,2),'rss_mib',round(int(rss)/1024,1),'memory',subprocess.check_output(['free','-m'],text=True).splitlines()[1],'test_query',probe_name,'NXDOMAIN',flush=True)
