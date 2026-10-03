/* SwiftProxy landing page — pure JS, no frameworks.
 * Note: this page deliberately stores NOTHING about visited sites
 * (no localStorage history, no cookies) — your browsing stays private. */
(function () {
  var form = document.getElementById('goform');
  var input = document.getElementById('url');
  if (!form || !input) return;

  // One-time cleanup: forget any browsing history stored by older versions.
  try { localStorage.removeItem('sp_recent'); } catch (e) {}

  function normalize(u) {
    u = (u || '').trim();
    if (!u) return u;
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(u)) u = 'https://' + u;
    return u;
  }

  form.addEventListener('submit', function () {
    var u = normalize(input.value);
    if (!u) return false;
    input.value = u;
  });

  var quicks = document.querySelectorAll('[data-quick]');
  for (var i = 0; i < quicks.length; i++) {
    (function (el) {
      el.addEventListener('click', function () { input.value = el.getAttribute('data-quick'); form.submit(); });
    })(quicks[i]);
  }

  input.focus();
})();
