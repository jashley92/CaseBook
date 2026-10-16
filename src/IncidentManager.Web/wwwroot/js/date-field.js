// BUG-408 / BUG-426: a date, time or datetime-local input that keeps what the user is typing. A Blazor @bind writes
// element.value back after every change it receives, and Chrome resets the segment being typed whenever a focused date input's value is set
// (typing "45" into the minutes gave "05"). Here the server never sets the value through the render tree: this module
// reports the user's changes and writes a value only when it differs from what the field already shows. A partly
// filled field (a segment cleared) reads as "" with validity.badInput; that isn't sent, so the bound value isn't
// blanked mid-edit, and the last good value comes back if the field is left that way. CSP-safe, no eval.
window.imDateField = (function () {
    const state = new WeakMap();   // element → { dotnet, last, seed }

    function attach(el, dotnet, initial) {
        if (!el) return;
        detach(el);
        const s = { dotnet: dotnet, last: initial || '', seed: initial || '' };
        if (el.value !== s.last) el.value = s.last;
        s.onInput = function () {
            const v = el.value;
            if (v === '' && el.validity && el.validity.badInput) return;   // mid-edit: one segment cleared
            if (refused(el, s, v)) return;   // BUG-606: mid-edit (a year half typed, "0202") or outside the field's years
            if (v === s.last) return;
            s.last = v;
            dotnet.invokeMethodAsync('Changed', v).catch(function () { /* circuit gone */ });
        };
        s.onBlur = function () {
            if (el.value === '' && el.validity && el.validity.badInput) { if (s.last) el.value = s.last; return; }
            if (!refused(el, s, el.value)) return;
            // BUG-614: a date outside the field's range is put back, and the field says why (it was put back silently).
            el.value = s.last;
            dotnet.invokeMethodAsync('Refused', el.min || '', el.max || '').catch(function () { /* circuit gone */ });
        };
        el.addEventListener('input', s.onInput);
        el.addEventListener('change', s.onInput);
        el.addEventListener('blur', s.onBlur);
        state.set(el, s);
    }

    // BUG-606: a value before the field's min or after its max. Same-format ISO text compares in date order.
    function outOfRange(el, v) {
        if (!v) return false;
        return (el.min && v < el.min) || (el.max && v.slice(0, el.max.length) > el.max);
    }

    // BUG-614: out of range, and not on the date the field was given (a stored date before 1970, or past the planning
    // max, keeps working: its time can be edited, or it can be left as it is).
    function refused(el, s, v) {
        return outOfRange(el, v) && !(s.seed && v.slice(0, 10) === s.seed.slice(0, 10));
    }

    // The server's value changed (a nudge button, a reset, an entry loaded to edit): show it, unless it's already shown.
    function set(el, value) {
        if (!el) return;
        const v = value || '';
        const s = state.get(el);
        if (s) { s.last = v; s.seed = v; }
        if (el.value !== v) el.value = v;
    }

    function detach(el) {
        const s = el && state.get(el);
        if (!s) return;
        el.removeEventListener('input', s.onInput);
        el.removeEventListener('change', s.onInput);
        el.removeEventListener('blur', s.onBlur);
        state.delete(el);
    }

    return { attach: attach, set: set, detach: detach };
})();
