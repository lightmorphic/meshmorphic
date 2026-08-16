// Polls for approval so the waiting device continues on its own once someone
// lets it in. Kept in a file rather than inline so the panel's content
// security policy can forbid inline script outright.
(function () {
  'use strict';
  var tries = 0;
  function check() {
    // Give up after ten minutes, which is when the code expires anyway.
    if (++tries > 200) { return; }
    fetch('/pair/status', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (data && data.approved) { window.location.href = '/'; return; }
        window.setTimeout(check, 3000);
      })
      .catch(function () { window.setTimeout(check, 5000); });
  }
  window.setTimeout(check, 3000);
})();
