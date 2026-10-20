// Administration: bring a setting into view when a search result, a Diagnostics fix link or an error's link lands on it.
// The settings load after the page does, so Admin.razor calls reveal once they're on the page. The id is the setting's key
// (it can hold ':'), so it's found by id, never a CSS selector.
window.imAdmin = {
    reveal: function (id) {
        if (!id) return false;
        var el = document.getElementById(id);
        if (!el) return false;
        var row = el.closest('.row') || el.closest('.card') || el;
        var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        row.scrollIntoView({ block: 'center', behavior: reduce ? 'auto' : 'smooth' });
        row.classList.add('adm-highlight');
        setTimeout(function () { row.classList.remove('adm-highlight'); }, 2500);
        if (typeof el.focus === 'function' && /^(INPUT|SELECT|TEXTAREA|BUTTON)$/.test(el.tagName)) el.focus({ preventScroll: true });
        return true;
    }
};
