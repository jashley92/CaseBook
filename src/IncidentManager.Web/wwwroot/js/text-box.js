// BUG-409: "[[" entity tagging for the plain one-line boxes (event steps, questions, the brief's parts, close-out),
// the same as the Markdown editors offer. Any textarea or input marked data-tag-box gets it. Typing "[[" and part of a
// name lists the case's entities; Up/Down to move, Enter/Tab/click to insert, Esc to close. It inserts "[[name]] ",
// which the server turns into a link on save (TagText.FromEditable), and raises "input" so a Blazor binding sees it.
// The case's entities come from TagBoxSource (imTagBox.setEntities). CSP-safe: pure DOM, no eval.
//
// BUG-412: lists in a plain Markdown box (the brief's parts, close-out), marked data-list-box. On a "- " or "1. " line,
// Enter starts the next item (and on an empty item ends the list), Tab makes it a sub-item and Shift+Tab takes it back
// out. Off a list line, Tab moves to the next field as usual.
(function () {
    const ITEM = /^(\s*)([-*+]|(\d{1,9})([.)]))(\s+)(\S.*|)$/;   // the content starts after the whole gap (no backtracking)
    const STEP = '    ';   // four spaces nest under "- ", "1. " and "10. " alike in CommonMark

    function lineAt(el) {
        const v = el.value, caret = el.selectionStart;
        const start = v.lastIndexOf('\n', caret - 1) + 1;
        let end = v.indexOf('\n', caret); if (end < 0) end = v.length;
        return { start: start, end: end, text: v.slice(start, end), caret: caret };
    }

    function replace(el, start, end, text, caret) {
        el.value = el.value.slice(0, start) + text + el.value.slice(end);
        el.setSelectionRange(caret, caret);
        el.dispatchEvent(new Event('input', { bubbles: true }));
    }

    window.addEventListener('keydown', e => {
        const el = e.target;
        if (e.defaultPrevented || !el || !el.matches || !el.matches('textarea[data-list-box]')) return;
        if (el.selectionStart !== el.selectionEnd || e.altKey || e.ctrlKey || e.metaKey) return;
        const line = lineAt(el), m = line.text.match(ITEM);
        if (!m) return;
        const [, indent, marker, num, delim, gap, content] = m;
        if (e.key === 'Enter' && !e.shiftKey) {
            if (line.caret < line.start + indent.length + marker.length) return;   // caret before the marker: a plain newline
            if (content.trim() === '') {   // an empty item ends the list (or steps out one level)
                if (indent.length > 0) {
                    const out = indent.slice(Math.min(indent.length, STEP.length));
                    replace(el, line.start, line.end, out + marker + gap, line.start + out.length + marker.length + gap.length);
                } else replace(el, line.start, line.end, '', line.start);
            } else {
                const next = num ? (Number(num) + 1) + delim : marker;
                const text = '\n' + indent + next + ' ';
                replace(el, line.caret, line.caret, text, line.caret + text.length);
            }
        } else if (e.key === 'Tab' && !e.shiftKey) {
            replace(el, line.start, line.start, STEP, line.caret + STEP.length);
        } else if (e.key === 'Tab' && e.shiftKey) {
            if (indent.length === 0) return;   // nothing to take out: Shift+Tab moves focus back
            const cut = indent.startsWith('\t') ? 1 : Math.min(indent.length, STEP.length);
            replace(el, line.start, line.start + cut, '', Math.max(line.start, line.caret - cut));
        } else return;
        e.preventDefault();
    }, false);
})();

// FR-49: a "[[" tag that names nothing on the case is offered as a new entity ('Add "j.ortiz" as Account'), here and in
// the Markdown editors (markdown-editor.js). The pick goes to the server (TagBoxSource.AddTagged), which adds it to the
// case, or matches the one already there, and the tag goes in as for any other entity. The types offered are guessed
// from the value; the first is the likeliest.
window.imTagAdd = (function () {
    let adder = null;   // DotNetObjectReference, set only for someone who can edit the case
    const LABELS = { Account: 'Account', Host: 'Host', IpAddress: 'IP address', Domain: 'Domain', Url: 'URL',
        FileHash: 'File hash', EmailAddress: 'Email address' };

    function types(v) {
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (/^[0-9a-f:]+$/i.test(v) && v.includes('::'))) return ['IpAddress'];
        if (/^(hxxps?|https?):\/\//i.test(v)) return ['Url'];
        if (/^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i.test(v)) return ['FileHash'];
        if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return ['Account', 'EmailAddress'];
        // first.last and host.domain look alike: a familiar top-level domain puts Domain first, else Account.
        if (/^[a-z0-9-]+(\[?\.\]?[a-z0-9-]+)+$/i.test(v))
            return /\.\]?(com|net|org|io|gov|edu|mil|co|uk|us|de|fr|ru|cn|info|biz|xyz|top|online|site|example|local|internal|corp)$/i.test(v)
                ? ['Domain', 'Host', 'Account'] : ['Account', 'Host', 'Domain'];
        return ['Account', 'Host'];
    }

    return {
        set: function (ref) { adder = ref || null; },
        // The "Add as" entries for a query that matched nothing exactly: [{ add, type, value, text }].
        offers: function (query, exact) {
            const v = String(query || '').trim();
            if (!adder || exact || v.length < 2 || /[\[\]\r\n]/.test(v)) return [];
            return types(v).map(t => ({ add: true, type: t, value: v, text: 'Add \u201c' + v + '\u201d as ' + LABELS[t] }));
        },
        // Resolves to { id, value, insert, label, hint }, or null when it couldn't be added.
        add: function (type, value) {
            return adder ? adder.invokeMethodAsync('AddTagged', type, value).catch(() => null) : Promise.resolve(null);
        }
    };
})();

window.imTagBox = (function () {
    let entities = [];   // { insert, label, hint }
    let menu = null, items = [], active = -1, field = null, from = -1, at = -1;
    const TRIGGER = /(?:^|[\s(])\[\[([^\[\]\r\n]{0,40})$/u;

    function close() { if (menu) { menu.remove(); menu = null; } items = []; active = -1; field = null; from = -1; at = -1; }

    // The "[[" the caret is in now: { caret, query, from }, or null.
    function trigger(el) {
        const caret = el.selectionStart;
        if (caret == null || el.selectionEnd !== caret) return null;
        const m = el.value.slice(0, caret).match(TRIGGER);
        return m ? { caret: caret, query: m[1], from: caret - m[1].length - 2 } : null;
    }

    function highlight() { if (menu) [...menu.children].forEach((el, i) => el.classList.toggle('active', i === active)); }

    // BUG-450: a box's save resolves a [[tag]] from what the box's text pointed at when it was opened (its refs) before
    // the case's entities, so a tag whose text is one of those labels (a citation of the same name, a renamed entity's
    // old label) would link there. The box lists those labels in data-tag-refs; such a pick goes in as its link instead.
    function insertFor(el, item) {
        const m = /^\[\[(.*)\]\]$/.exec(item.insert || '');
        if (!m || !item.link) return item.insert;
        const tag = m[1].toLowerCase();
        const refs = (el.getAttribute('data-tag-refs') || '').split('\n');
        return refs.some(r => r.toLowerCase() === tag) ? item.link : item.insert;
    }

    function choose(i) {
        if (!field || !items[i]) return close();
        if (items[i].add) {   // FR-49: added on the server first, then inserted as any other entity's tag
            const offer = items[i], el = field, f = from;
            window.imTagAdd.add(offer.type, offer.value).then(r => {
                if (!r || !menu) return close();
                field = el; from = f;
                items[i] = { insert: r.insert, label: r.label, hint: r.hint };
                entities.push(items[i]);
                choose(i);
            });
            return;
        }
        // BUG-430: the caret may have moved since the list was drawn (arrow keys, a click, Home/End); insert only at the
        // "[[" it is in now, so text elsewhere isn't overwritten.
        const el = field, t = trigger(el);
        if (!t || t.from !== from) return close();
        const start = t.from, end = t.caret;
        let after = el.value.slice(end);
        if (after.startsWith(']]')) after = after.slice(2);   // a closer already typed is taken with the tag
        const text = insertFor(el, items[i]) + ' ';   // [[tag]], or the link itself for a shared name (BUG-423)
        el.value = el.value.slice(0, start) + text + after;
        const caret = start + text.length;
        try { el.setSelectionRange(caret, caret); } catch (e) { /* not a text field */ }
        close();
        // Both, so a binding on either event sees the text (a script-set value raises no change event on blur).
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        el.focus();
    }

    function update(el) {
        const t = trigger(el);
        if (!t) return close();
        const q = t.query.toLowerCase();
        const exact = entities.some(c => c.label.toLowerCase() === q.trim());
        const matches = entities.filter(c => q === '' || c.label.toLowerCase().includes(q) || (c.hint || '').toLowerCase().includes(q)).slice(0, 8)
            .concat(window.imTagAdd.offers(t.query, exact));
        if (matches.length === 0) return close();
        field = el; from = t.from; at = t.caret; items = matches; active = 0;
        if (!menu) { menu = document.createElement('div'); menu.className = 'cm-mention-menu'; menu.setAttribute('role', 'listbox'); document.body.appendChild(menu); }
        menu.innerHTML = '';
        matches.forEach((c, i) => {
            const it = document.createElement('div');
            it.className = 'cm-mention-item' + (i === 0 ? ' active' : '');
            it.setAttribute('role', 'option');
            it.textContent = c.add ? c.text : c.hint ? (c.label + '  ·  ' + c.hint) : c.label;
            if (c.add) it.classList.add('cm-mention-add');
            it.title = it.textContent;   // a long value is cut short in the list
            it.addEventListener('mousedown', ev => { ev.preventDefault(); choose(i); });
            menu.appendChild(it);
        });
        // Under the field (a textarea's caret position isn't exposed), kept on screen.
        const r = el.getBoundingClientRect();
        menu.style.left = (window.scrollX + r.left) + 'px';
        menu.style.top = (window.scrollY + r.bottom + 2) + 'px';
    }

    const isBox = t => t && t.matches && t.matches('textarea[data-tag-box], input[data-tag-box]');

    document.addEventListener('input', e => { if (isBox(e.target) && e.isTrusted) update(e.target); }, true);
    document.addEventListener('click', e => { if (menu && e.target !== field) close(); }, true);
    // BUG-430: a caret moved without typing (a click in the box, Left/Right, Home/End) re-reads the trigger, closing the
    // list once the caret has left the "[[". Up/Down only move through the list, so they leave the caret where it was.
    const moved = e => { if (menu && e.target === field && (field.selectionStart !== at || field.selectionEnd !== at)) update(field); };
    document.addEventListener('keyup', moved, true);
    document.addEventListener('mouseup', moved, true);
    document.addEventListener('focusout', e => { if (e.target === field) setTimeout(() => { if (document.activeElement !== field) close(); }, 150); }, true);
    // Window capture runs before the keymap's handlers, so Enter picks a tag instead of saving the form.
    window.addEventListener('keydown', e => {
        if (!menu || e.target !== field) return;
        if (e.key === 'ArrowDown') { active = (active + 1) % items.length; highlight(); }
        else if (e.key === 'ArrowUp') { active = (active - 1 + items.length) % items.length; highlight(); }
        else if ((e.key === 'Enter' && !e.ctrlKey && !e.metaKey) || e.key === 'Tab') { choose(active); }
        else if (e.key === 'Escape') { close(); }
        else return;
        e.preventDefault(); e.stopImmediatePropagation();
    }, true);

    return {
        setEntities: function (list) { entities = Array.isArray(list) ? list : []; close(); },
        setAdder: function (ref) { window.imTagAdd.set(ref); }
    };
})();

// BUG-605: a large text box's value, read as a stream (IJSStreamReference) rather than sent in a Blazor event, which is
// capped at the hub's 32 KB message size; and set from the server for display.
window.imTextValue = {
    read: function (id) {
        const el = document.getElementById(id);
        return new TextEncoder().encode(el ? el.value : '');
    },
    set: function (id, value) {
        const el = document.getElementById(id);
        if (el && el.value !== value) el.value = value || '';
    }
};
