/* Domain filters: no remote strings enter HTML or event-handler attributes. */
(() => {
    'use strict';
    const page = document.getElementById('filter-page');
    if (!page) return;
    let busy = false;
    const get = id => document.getElementById(id);
    const element = (tag, text, className) => {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        if (className) node.className = className;
        return node;
    };
    function notice(message, error = false) {
        get('filter-notice').textContent = message;
        get('filter-notice').className = 'alert ' + (error ? 'alert-danger' : 'alert-info');
    }
    function draw(state, editors = true) {
        get('filter-count').textContent = state.effective_count.toLocaleString() + ' blocked rules';
        if (editors) {
            get('filter-blocked').value = state.blocked.join('\n');
            get('filter-allowed').value = state.allowed.join('\n');
        }
        const list = get('filter-lists');
        list.replaceChildren();
        if (!state.initialized) notice('Managed config is not initialized. Ask the administrator to create the empty filter fragment before applying changes.', true);
        if (!state.lists.length) list.append(element('p', 'No subscriptions added.', 'text-dim'));
        for (const item of state.lists) {
            const card = element('section', undefined, 'card filter-subscription');
            const head = element('div', undefined, 'card-header');
            head.append(element('h3', item.name), element('span', item.enabled ? 'Enabled' : 'Disabled', 'badge badge-' + (item.enabled ? 'orange' : 'gray')));
            const body = element('div', undefined, 'card-body');
            body.append(element('p', item.url, 'text-mono text-dim filter-url'));
            const date = value => value ? new Date(value).toLocaleString() : 'Never';
            body.append(element('p', `${item.count.toLocaleString()} cached domains · Last success: ${date(item.last_updated)} · Last attempt: ${date(item.last_attempt)}`, 'text-dim mt-1'));
            if (item.unsupported) {
                const warnings = element('details', undefined, 'mt-1 text-orange');
                warnings.append(element('summary', `${item.unsupported} unsupported lines skipped (not full Adblock syntax)`));
                for (const sample of item.samples) warnings.append(element('p', sample, 'text-mono filter-url'));
                body.append(warnings);
            }
            if (item.last_error) body.append(element('p', 'Last error: ' + item.last_error + '. Last good cache was preserved.', 'alert alert-warning mt-1'));
            const actions = element('div', undefined, 'btn-group filter-actions mt-2');
            function action(label, path, payload, confirmMessage) {
                const button = element('button', label, 'btn btn-ghost');
                button.type = 'button';
                button.addEventListener('click', () => {
                    if (confirmMessage && !window.confirm(confirmMessage)) return;
                    mutate(`/api/filters/lists/${item.id}/${path}`, payload, label + ' complete.', false);
                });
                actions.append(button);
                return button;
            }
            action('Refresh now', 'refresh', {});
            const toggle = action(item.enabled ? 'Disable & apply' : 'Enable & apply', 'enabled', {enabled: !item.enabled});
            toggle.disabled = !item.enabled && item.count === 0;
            if (toggle.disabled) toggle.title = 'Refresh successfully before enabling';
            action('Delete', 'delete', {}, `Delete “${item.name}” and remove its active rules?`);
            body.append(actions);
            card.append(head, body);
            list.append(card);
        }
    }
    async function request(path, payload) {
        const options = {redirect: 'manual', headers: {'X-Requested-With': 'XMLHttpRequest'}};
        if (payload !== undefined) {
            options.method = 'POST';
            options.headers['Content-Type'] = 'application/json';
            options.headers['X-CSRF-Token'] = document.querySelector('meta[name="csrf-token"]').content;
            options.body = JSON.stringify(payload);
        }
        const response = await fetch(path, options);
        if (response.type === 'opaqueredirect' || [302, 307, 401].includes(response.status)) {
            window.location.assign('/login?next=/filters');
            throw new Error('Your session expired. Sign in again.');
        }
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(typeof data.detail === 'string' ? data.detail : (data.error || 'Request failed. Check your input.'));
        return data.state;
    }
    async function mutate(path, payload, done, editors = true) {
        if (busy) return;
        busy = true;
        page.setAttribute('aria-busy', 'true');
        const controls = Array.from(page.querySelectorAll('button, input, textarea')).map(node => [node, node.disabled]);
        controls.forEach(([node]) => { node.disabled = true; });
        notice('Working… Downloads and configuration validation can take up to a minute. Do not repeat the action.');
        try {
            const state = await request(path, payload);
            draw(state, editors);
            notice(done || 'Updated.');
        } catch (error) {
            notice(error.message, true);
            try { draw(await request('/api/filters'), false); } catch (_) { /* keep original error */ }
        } finally {
            busy = false;
            page.removeAttribute('aria-busy');
            controls.forEach(([node, disabled]) => { node.disabled = disabled; });
        }
    }
    for (const kind of ['blocked', 'allowed']) {
        get(`filter-${kind}-form`).addEventListener('submit', event => {
            event.preventDefault();
            const domains = get(`filter-${kind}`).value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
            mutate('/api/filters/domains', {kind, domains}, 'Domains validated, saved and applied.');
        });
    }
    get('filter-subscription-form').addEventListener('submit', async event => {
        event.preventDefault();
        await mutate('/api/filters/lists', {name: get('filter-list-name').value.trim(), url: get('filter-list-url').value.trim()}, 'Disabled list added. Refresh it, then enable it.', false);
    });
    request('/api/filters').then(state => {
        notice('Ready. No subscriptions are enabled automatically. Saving domain rules or toggling a list applies DNS changes.');
        draw(state);
    }).catch(error => notice(error.message, true));
})();
