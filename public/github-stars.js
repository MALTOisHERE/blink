// ── GitHub star count ────────────────────────────────────────────────────────
// Fills in the live star count on the header's GitHub link. Each visitor's
// own browser calls the GitHub API directly (not our server), so this never
// touches our own rate limits - only GitHub's public, unauthenticated one
// (60 req/hour per visitor IP), which a short localStorage cache keeps this
// well under even for a visitor browsing multiple pages in one sitting.
(() => {
  const el = document.getElementById('github-stars-count');
  if (!el) return;

  const CACHE_KEY = 'blink-github-stars';
  const CACHE_TTL = 3_600_000; // 1 hour

  function formatCount(n) {
    if (n >= 1000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
    return String(n);
  }

  function render(count) {
    el.textContent = formatCount(count);
  }

  try {
    const cached = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null');
    if (cached && Date.now() - cached.at < CACHE_TTL) {
      render(cached.count);
      return;
    }
  } catch {}

  fetch('https://api.github.com/repos/MALTOisHERE/onlyonce')
    .then(r => (r.ok ? r.json() : Promise.reject(r.status)))
    .then(data => {
      const count = data.stargazers_count;
      if (typeof count !== 'number') return;
      render(count);
      try { localStorage.setItem(CACHE_KEY, JSON.stringify({ count, at: Date.now() })); } catch {}
    })
    .catch(() => {}); // leave the badge star-less rather than show a broken count
})();
