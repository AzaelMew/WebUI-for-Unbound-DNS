import pathlib, subprocess, time, socket, resource, os, tempfile, signal
from filters import download_list, parse_list, render_config
url='https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt'
start=time.monotonic(); raw=download_list(url); parsed=parse_list(raw); config, effective=render_config(parsed['domains'], [])
with tempfile.TemporaryDirectory(prefix='tif-mini-probe-', dir='/opt/unbound-webui') as td:
    root=pathlib.Path(td); (root/'zones').mkdir(); (root/'zones'/'filters.conf').write_text(config)
    main=root/'unbound.conf'
    main.write_text(f'''server:\n    interface: 127.0.0.1\n    port: 53536\n    username: "unbound"\n    directory: "{root}"\n    chroot: ""\n    pidfile: "{root}/unbound.pid"\n    module-config: "validator iterator"\ninclude: "{root}/zones/filters.conf"\n''')
    subprocess.run(['unbound-checkconf',str(main)],check=True,capture_output=True,text=True)
    before=time.monotonic(); proc=subprocess.Popen(['/usr/sbin/unbound','-d','-c',str(main)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    ready=False
    for _ in range(300):
        if proc.poll() is not None: raise RuntimeError(proc.stderr.read())
        try:
            with socket.create_connection(('127.0.0.1',53536),timeout=.1): ready=True;break
        except OSError: time.sleep(.1)
    startup=time.monotonic()-before
    if not ready: raise RuntimeError('Unbound startup exceeded 30 seconds')
    rss=subprocess.check_output(['ps','-o','rss=','-p',str(proc.pid)],text=True).strip()
    query=subprocess.run(['dig','+time=1','+tries=1','@127.0.0.1','-p','53536','blocked.example.invalid','A','+comments','+noquestion','+nostats'],capture_output=True,text=True).stdout
    assert 'status: NXDOMAIN' in query,query
    print({'list_bytes':len(raw),'domains':len(parsed['domains']),'unsupported':parsed['unsupported'],'generated_config_bytes':len(config),'download_parse_seconds':round(before-start,1),'isolated_unbound_startup_seconds':round(startup,1),'isolated_unbound_rss_mib':round(int(rss)/1024,1),'test_query':'NXDOMAIN'})
    proc.terminate();proc.wait(timeout=5);proc.stderr.close()
