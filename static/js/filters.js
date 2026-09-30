/* Domain filters: no remote strings enter HTML or event-handler attributes. */
(() => {
    'use strict';
    const page = document.getElementById('filter-page');
    if (!page) return;
    let busy = false;
    const lockedControls = new Map();
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
    const mib = bytes => (Number(bytes || 0) / 1048576).toLocaleString(undefined, {maximumFractionDigits: 2});
    const sourcesFor = item => Array.isArray(item.sources) ? item.sources : [item.url];
    const sourceLines = value => value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    function lockControls(root = page) {
        if (!busy) return;
        for (const control of root.querySelectorAll('button, input, textarea, select')) {
            if (!lockedControls.has(control)) lockedControls.set(control, control.disabled);
            control.disabled = true;
        }
    }
    function editSubscription(item, index) {
        const form = element('form', undefined, 'mt-2');
        form.hidden = true;
        const field = (tag, label, suffix) => {
            const row = element('div', undefined, 'form-row');
            const input = element(tag, undefined, 'form-control');
            input.id = `filter-edit-${index}-${suffix}`;
            input.required = true;
            const caption = element('label', label, 'form-label');
            caption.htmlFor = input.id;
            row.append(caption, input);
            form.append(row);
            return input;
        };
        const name = field('input', 'List name', 'name');
        name.value = item.name;
        name.maxLength = 100;
        name.autocomplete = 'off';
        const sources = field('textarea', 'Public HTTPS sources (one per line)', 'sources');
        sources.value = sourcesFor(item).join('\n');
        sources.rows = 3;
        sources.spellcheck = false;
        const format = field('select', 'Feed format', 'format');
        for (const [value, label] of [
            ['auto', 'Auto-detect'], ['domains', 'Plain domains'], ['hosts', 'Hosts'],
            ['adblock', 'Adblock (domain rules only)'], ['rpz', 'RPZ (supported blocking records only)']
        ]) {
            const option = element('option', label);
            option.value = value;
            format.append(option);
        }
        format.value = item.format || 'auto';
        form.append(element('p', 'Changing sources or format disables the subscription and discards its old cache. Refresh successfully before enabling it again. Renaming alone preserves the cache and enabled state.', 'text-dim text-sm mt-1'));
        const actions = element('div', undefined, 'btn-group filter-actions mt-2');
        const save = element('button', 'Save subscription', 'btn btn-orange');
        save.type = 'submit';
        const cancel = element('button', 'Cancel edit', 'btn btn-ghost');
        cancel.type = 'button';
        cancel.addEventListener('click', () => { if (!busy) form.hidden = true; });
        actions.append(save, cancel);
        form.append(actions);
        form.addEventListener('submit', event => {
            event.preventDefault();
            if (busy) return;
            const payload = {name: name.value.trim(), sources: sourceLines(sources.value), format: format.value};
            const changed = payload.format !== (item.format || 'auto') || JSON.stringify(payload.sources) !== JSON.stringify(sourcesFor(item));
            if (changed && !window.confirm('Changing sources or format will disable this subscription, remove its active rules and discard its old cache. Refresh successfully before enabling it again. Continue?')) return;
            mutate(`/api/filters/lists/${encodeURIComponent(item.id)}/edit`, payload,
                changed ? 'Subscription saved and disabled. Refresh it, then enable it.' : 'Subscription renamed. Cache and enabled state preserved.', false);
        });
        return form;
    }
    function draw(state, editors = true) {
        get('filter-count').textContent = state.effective_count.toLocaleString() + ' blocked rules';
        const limits = state.limits;
        get('filter-limits').textContent = limits
            ? `Limits: ${mib(limits.max_bytes)} MiB per source, ${mib(limits.max_total_bytes ?? limits.max_bytes)} MiB per subscription refresh (all sources combined), ${limits.max_entries.toLocaleString()} unique domains across all cached subscriptions and manual rules, ${limits.max_subscriptions.toLocaleString()} subscriptions, ${limits.max_sources.toLocaleString()} sources per subscription.`
            : 'Safety limits are unavailable. Ask the administrator to verify the server configuration.';
        const interval = Number(state.refresh_interval_seconds || 0);
        get('filter-refresh-policy').textContent = interval > 0
            ? `Automatic refresh is configured globally by the administrator: every ${interval.toLocaleString()} seconds for enabled subscriptions. Disabled subscriptions require Refresh now.`
            : 'Automatic refresh is off. Refresh now is manual; an administrator must explicitly configure a global interval to enable scheduled refreshes.';
        if (editors) {
            get('filter-blocked').value = state.blocked.join('\n');
            get('filter-allowed').value = state.allowed.join('\n');
        }
        const list = get('filter-lists');
        list.replaceChildren();
        if (!state.initialized) notice('Managed config is not initialized. Ask the administrator to create the empty filter fragment before applying changes.', true);
        if (!state.lists.length) list.append(element('p', 'No subscriptions added.', 'text-dim'));
        for (const [index, item] of state.lists.entries()) {
            const card = element('section', undefined, 'card filter-subscription');
            const head = element('div', undefined, 'card-header');
            head.append(element('h3', item.name), element('span', item.enabled ? 'Enabled' : 'Disabled', 'badge badge-' + (item.enabled ? 'orange' : 'gray')));
            const body = element('div', undefined, 'card-body');
            const sources = sourcesFor(item);
            body.append(element('p', `Format: ${item.format || 'auto'} · ${sources.length} ${sources.length === 1 ? 'source' : 'sources'} · ${mib(item.downloaded_bytes)} MiB downloaded`, 'text-dim'));
            for (const source of sources) body.append(element('p', source, 'text-mono text-dim filter-url mt-1'));
            const date = value => value ? new Date(value).toLocaleString() : 'Never';
            body.append(element('p', `${item.count.toLocaleString()} cached domains · Last success: ${date(item.last_updated)} · Last attempt: ${date(item.last_attempt)}`, 'text-dim mt-1'));
            if (item.unsupported) {
                const warnings = element('details', undefined, 'mt-1 text-orange');
                warnings.append(element('summary', `${item.unsupported} unsupported lines skipped (only supported domain-blocking syntax is imported)`));
                for (const sample of item.samples || []) warnings.append(element('p', sample, 'text-mono filter-url'));
                body.append(warnings);
            }
            if (item.last_error) {
                const cacheStatus = item.count > 0
                    ? 'Last good cache was preserved.'
                    : 'No cached domains. Refresh successfully before enabling.';
                body.append(element('p', `Last error: ${item.last_error}. ${cacheStatus}`, 'alert alert-warning mt-1'));
            }
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
            const form = editSubscription(item, index);
            const edit = element('button', 'Edit', 'btn btn-ghost');
            edit.type = 'button';
            edit.addEventListener('click', () => { if (!busy) form.hidden = !form.hidden; });
            actions.append(edit);
            body.append(actions, form);
            card.append(head, body);
            lockControls(card);
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
        lockControls();
        notice('Working… Bounded downloads, configuration validation and activation can take several minutes for large feeds. Do not repeat the action.');
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
            for (const [node, disabled] of lockedControls) node.disabled = disabled;
            lockedControls.clear();
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
        await mutate('/api/filters/lists', {
            name: get('filter-list-name').value.trim(),
            sources: sourceLines(get('filter-list-sources').value),
            format: get('filter-list-format').value
        }, 'Disabled list added. Refresh it, then enable it.', false);
    });
    request('/api/filters').then(state => {
        notice('Ready. No subscriptions are enabled automatically. Saving domain rules or toggling a list applies DNS changes.');
        draw(state);
    }).catch(error => notice(error.message, true));
})();
