"""TLS-only launcher for the audited upstream WebUI."""
import os
import secrets
from pathlib import Path

os.umask(0o077)
BASE = Path(__file__).resolve().parent
os.chdir(BASE)
# Bind locally by default. A systemd drop-in may opt into a LAN address after
# adding a matching firewall rule; never bake one operator's LAN addresses in.
BIND_HOST = os.environ.get('WEBUI_LISTEN_HOST', '127.0.0.1')
BIND_PORT = int(os.environ.get('WEBUI_LISTEN_PORT', '8443'))
BOOTSTRAP_IP = os.environ.get('WEBUI_BOOTSTRAP_IP', '127.0.0.1')
os.environ['WEBUI_BOOTSTRAP_IP'] = BOOTSTRAP_IP
from auth import change_password
if not (BASE / '.configured').exists():
    # Disable upstream's default credentials before app import or listener startup.
    change_password('admin', secrets.token_urlsafe(48))
import app as upstream
from safety import install
from container_memory import install as install_container_memory
from filters import install as install_filters
from filter_refresh import install as install_filter_refresh
from ssl_utils import ensure_ssl_cert
import uvicorn
install(upstream)
install_container_memory(upstream)
filter_manager = install_filters(upstream)
filter_refresh_worker = install_filter_refresh(upstream.app, filter_manager)
cert, key = ensure_ssl_cert()
if __name__ == '__main__':
    if os.environ.get('WEBUI_HTTP_REDIRECT', '').lower() in {'1', 'true', 'yes'}:
        upstream.run_http_redirect(int(os.environ.get('WEBUI_HTTP_PORT', '8080')), BIND_PORT)
    uvicorn.run(upstream.app, host=BIND_HOST, port=BIND_PORT,
                ssl_certfile=cert, ssl_keyfile=key, proxy_headers=False,
                log_level='info', access_log=False)
