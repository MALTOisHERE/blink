// ── Changelog page ───────────────────────────────────────────────────────────
// Loads the pre-rendered changelog partial (regenerated from commit history
// by the release workflow) and drops it into the page. If it hasn't been
// generated yet (e.g. before the first release since this feature shipped),
// fall back to linking out to GitHub Releases.
(() => {
  const list = document.getElementById('changelog-list');
  if (!list) return;

  fetch('/changelog-data.html')
    .then(r => { if (!r.ok) throw new Error('not found'); return r.text(); })
    .then(html => {
      if (!html.trim()) throw new Error('empty');
      list.innerHTML = html;
    })
    .catch(() => {
      list.innerHTML = '';
      const empty = document.createElement('div');
      empty.className = 'changelog-empty';
      empty.textContent = 'No changelog generated yet. ';
      const link = document.createElement('a');
      link.href = 'https://github.com/MALTOisHERE/onlyonce/releases';
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.className = 'footer-link';
      link.textContent = 'See releases on GitHub';
      empty.appendChild(link);
      list.appendChild(empty);
    });
})();
