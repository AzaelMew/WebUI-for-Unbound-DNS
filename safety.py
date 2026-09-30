"""Local deployment policy; keep upstream files separately auditable."""
import os
import re
import shutil
import stat
import tarfile
import tempfile
import threading
import uuid
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from fastapi import HTTPException, Depends
from fastapi.responses import JSONResponse, RedirectResponse

_LOCK = threading.RLock()


def _safe_path(upstream, value):
    path = Path(value).resolve()
    roots = [Path(upstream.DEFAULT_CONFIG_FILE).resolve().parent,
             Path(upstream.DEFAULT_CONFIG_DIR).resolve()]
    if path.suffix != '.conf' or not any(path.is_relative_to(root) for root in roots):
        raise ValueError('Configuration must be a .conf file within the Unbound directory')
    return str(path)


def _atomic_write(path, content):
    info = path.stat()
    fd, name = tempfile.mkstemp(prefix='.webui-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(handle.fileno(), info.st_uid, info.st_gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _validated_write(upstream, value, content, activate=False):
    target = Path(_safe_path(upstream, value))
    main = Path(upstream.DEFAULT_CONFIG_FILE).resolve()
    root = main.parent
    if not target.is_file() or target.is_symlink():
        raise HTTPException(400, 'Only existing regular configuration files may be edited')
    with _LOCK:
        with tempfile.TemporaryDirectory(prefix='.validate-', dir=upstream.BACKUP_DIR) as tmp:
            stage = Path(tmp) / 'unbound'
            shutil.copytree(root, stage, symlinks=False)
            staged_target = stage / target.relative_to(root)
            staged_target.write_text(content)
            # Only relocate include directives; leave certificate/trust-anchor paths intact.
            for conf in stage.rglob('*.conf'):
                conf.write_text(re.sub(r'(?m)^(\s*include(?:-toplevel)?:\s*)(.*)$',
                    lambda m: m.group(1) + m.group(2).replace(str(root) + '/', str(stage) + '/'),
                    conf.read_text()))
            for cfg in dict.fromkeys([stage / main.relative_to(root), staged_target]):
                out, err, rc = upstream.run_cmd(['unbound-checkconf', str(cfg)])
                if rc:
                    raise HTTPException(422, upstream._clean_error('Config validation failed; original untouched', err or out))
        backup = Path(upstream.BACKUP_DIR) / ('full_config_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:8] + '.tgz')
        with tarfile.open(backup, 'x:gz') as archive:
            archive.add(root, arcname='unbound')
        backup.chmod(0o600)
        original = target.read_bytes()
        try:
            _atomic_write(target, content.encode())
            out, err, rc = upstream.run_cmd(['unbound-checkconf', str(main)])
            if rc:
                raise HTTPException(422, upstream._clean_error('Live validation failed', err or out))
            if activate:
                out, err, rc = upstream.run_cmd(['systemctl', 'reload-or-restart', 'unbound'])
                if rc:
                    raise HTTPException(500, upstream._clean_error('Activation failed', err or out))
        except Exception:
            _atomic_write(target, original)
            if activate:
                upstream.run_cmd(['systemctl', 'reload-or-restart', 'unbound'])
            raise
        return backup.name

BLOCKED = {
    '/api/config/save', '/api/config/apply', '/api/config/create_file',
    '/api/config/delete_file', '/api/config/includes/save',
    '/api/config/subfile/update_tabs', '/api/unbound/certs/delete',
    '/api/unbound/certs/regenerate', '/api/ssl/regenerate',
}


def install(upstream):
    for middleware in upstream.app.user_middleware:
        if middleware.cls is upstream.SessionMiddleware:
            middleware.kwargs['https_only'] = True
    upstream._safe_config_path = lambda value: _safe_path(upstream, value)
    replacements = {'/api/config/raw/save', '/api/backup/restore', '/login'}
    upstream.app.router.routes[:] = [r for r in upstream.app.router.routes
                                    if not (getattr(r, 'path', '') in replacements and
                                            'POST' in getattr(r, 'methods', set()))]
    attempts = defaultdict(deque)

    marker = upstream.BASE_DIR / '.configured'

    def bootstrap_access(request):
        if marker.exists():
            raise HTTPException(404, 'Setup is already complete')
        if request.client.host != os.environ.get('WEBUI_BOOTSTRAP_IP', request.client.host):
            raise HTTPException(403, 'Initial setup is restricted to the administrator PC')

    @upstream.app.get('/setup')
    async def setup_get(request: upstream.Request):
        bootstrap_access(request)
        return upstream._template(request, 'setup.html', {})

    @upstream.app.post('/setup')
    async def setup_post(request: upstream.Request):
        bootstrap_access(request)
        form = await request.form()
        token = str(form.get('csrf_token', ''))
        expected = request.session.get('csrf_token', '')
        if not expected or not secrets.compare_digest(token, expected):
            raise HTTPException(403, 'Setup CSRF validation failed')
        password = str(form.get('password', ''))
        if len(password) < 12 or len(password) > 128:
            raise HTTPException(422, 'Use a password between 12 and 128 characters')
        with _LOCK:
            bootstrap_access(request)
            upstream.change_password('admin', password)
            marker.write_text('Administrator configured\n')
            marker.chmod(0o600)
        request.session.clear()
        return RedirectResponse('/login', status_code=303)

    @upstream.app.post('/login')
    async def safe_login(request: upstream.Request):
        form = await request.form()
        supplied = str(form.get('csrf_token', ''))
        expected = request.session.get('csrf_token', '')
        if not expected or not secrets.compare_digest(supplied, expected):
            raise HTTPException(403, 'Login CSRF validation failed')
        key = request.client.host
        now = time.monotonic()
        bucket = attempts[key]
        while bucket and now - bucket[0] > 300:
            bucket.popleft()
        if len(bucket) >= 10:
            raise HTTPException(429, 'Too many login attempts; wait five minutes')
        bucket.append(now)
        dest = str(form.get('next', '/'))
        if not dest.startswith('/') or dest.startswith('//'):
            dest = '/'
        response = await upstream.login_post(request, str(form.get('username', '')),
                                             str(form.get('password', '')), dest)
        if response.status_code == 302:
            bucket.clear()
        return response

    @upstream.app.post('/api/config/raw/save')
    async def raw_save(request: upstream.Request, payload: upstream.RawConfigPayload,
                       _user=Depends(upstream._login_required), _csrf=Depends(upstream._verify_csrf)):
        backup = _validated_write(upstream, upstream.get_config_file(request), payload.content)
        return {'success': True, 'backup': backup, 'message': 'Validated and saved. Reload Unbound to activate.'}

    @upstream.app.post('/api/backup/restore')
    async def restore(request: upstream.Request, payload: upstream.RestorePayload,
                      _user=Depends(upstream._login_required), _csrf=Depends(upstream._verify_csrf)):
        source = Path(upstream.BACKUP_DIR) / payload.filename
        if not source.is_file():
            raise HTTPException(404, 'Backup file not found')
        _validated_write(upstream, upstream.get_config_file(request), source.read_text(), activate=True)
        return {'success': True}

    @upstream.app.middleware('http')
    async def deployment_policy(request, call_next):
        path = request.url.path
        if path == '/api/debug/run' and request.method == 'POST':
            data = await request.json()
            if str(data.get('target', '')).startswith('-'):
                return JSONResponse({'detail': 'Command options are not valid DNS targets'}, status_code=422)
        if request.method == 'POST' and (path in BLOCKED or
                (path.startswith('/api/system/') and path.rsplit('/', 1)[-1]
                 not in {'flush_dns', 'flush_cache', 'dump_cache'})):
            return JSONResponse({'detail': 'Disabled to preserve the existing DNS configuration. Use the validated Raw Editor for edits.'}, status_code=403)
        return await call_next(request)
