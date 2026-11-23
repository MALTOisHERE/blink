# Changelog

All notable changes to Blink, generated automatically from commit history on every release.

## v2.1.0 - 2026-11-23

### Bug Fixes

- Pin Docker base image by digest instead of a floating tag

- Validate structure of restored secrets-snapshot entries

- Account for per-secret overhead in memory-capacity accounting

- Harden OAuth sign-in (PKCE, per-provider cookies, fuller token checks, timeouts)

- Make reverse-proxy trust configurable instead of hardcoding one hop count

- Key OTP hashes with K3 instead of plain SHA-256

- Close TOCTOU race in secret-creation capacity checks

- Restrict permissions on persisted license/snapshot/stats files

- Require SECRET_KEY/CIPHER_KEY in production instead of degrading silently


### Documentation

- Add GLOSSARY.md

- Fix stale README line claiming CI auto-publishes images on push

- Regenerate changelog for v2.0.10


### Maintenance

- Generate and attach an SBOM when publishing the image


### Other

- Constrain centered reveal cards

Limit reveal, secret, expired, cleared, and file-reveal cards to 480px and center them, while keeping the OTP/passphrase entry card full-width.

- Update manifest.json


## v2.0.10 - 2026-11-22

### Bug Fixes

- Correct git-cliff template variable names, verified against the real binary


### Documentation

- Document the commit-prefix convention the changelog relies on


### Features

- Add a changelog page, generated from commit history via git-cliff


## v2.0.9 - 2026-11-21

### Bug Fixes

- Exclude / from COEP header, same as /about already was


## v2.0.8 - 2026-11-21

### Features

- Show the demo video as a one-time popup for first-time visitors


## v2.0.7 - 2026-11-21

### Bug Fixes

- Stop browser treating email+passphrase fields as a login form, add show/hide toggle


## v2.0.6 - 2026-11-21

### Bug Fixes

- Make email branding configurable instead of hardcoded to this deployment

- Stop hardcoding HOST and EMAIL_FROM in docker-compose.yml


## v2.0.5 - 2026-11-21

### Bug Fixes

- Run as the base image's own node user instead of an ad-hoc one


### Maintenance

- Default to latest tag again instead of resolving current commit

- Make build (image publish) manual too, not tied to push

- Build-once image-based deploys instead of git pull + build on the VPS


## v2.0.4 - 2026-11-21

### Bug Fixes

- Render email logo as square instead of forced 47x32


## v2.0.3 - 2026-11-21

### Maintenance

- Add job summaries to every workflow

- Remove em dashes from user-facing docs and log messages


## v2.0.2 - 2026-11-21

### Bug Fixes

- Pin GitHub Actions to commit SHAs, remove shell-injection risk, set explicit GCM tag length

- Close reveal-order bypass, log redaction gap, and unbounded memory growth


## v2.0.1 - 2026-11-19

### Other

- Document client-side decryption flow

Update the README, about page, and llms.txt to explain K1 hash verification, server-side release of encrypted data, and decryption in the recipient's browser.


## v2.0.0 - 2026-11-19

### Other

- Move secret decryption entirely to clients

Verify reveal requests with SHA-256(K1), then release K2 and ciphertext for browser-side decryption. Update tests and architecture documentation for the end-to-end flow.


## v1.2.13 - 2026-11-14

### Features

- Add GitHub star button and live count to header across multiple pages


## v1.2.12 - 2026-11-14

### Other

- Update Blink branding assets

Use MALTO's SVG logo for the extension, site branding, favicons, social previews, and manifest icons. Keep the existing Blink logo in email headers.


## v1.2.11 - 2026-11-14

### Other

- Update about.html

- Expand about video to container width

Remove the 640px width cap and centered margins from the about video wrapper so it fills its container, and use the surface color instead of black for its background.


## v1.2.10 - 2026-11-08

### Other

- Skip COEP on the about page

Allow the YouTube embed on /about to load by omitting Cross-Origin-Embedder-Policy there, while retaining it on other routes.


## v1.2.9 - 2026-11-08

### Other

- Upgrade Resend to v6

Update the Resend dependency to ^6.37.0.


## v1.2.8 - 2026-11-08

### Other

- Embed demo video on about page

Add a responsive YouTube privacy-enhanced video embed and allow its domain in the content security policy.


## v1.2.7 - 2026-10-21

### Other

- Document modules and clean up lint findings

Add concise module and test descriptions, update Biome rules and overrides, and clean up lint-related syntax and Node.js imports across the app and browser extension.


## v1.2.6 - 2026-10-21

### Other

- Expand tests and lint frontend scripts

Add coverage for authentication, licensing, OTP, file secrets, rate limits, and graceful restarts. Extend ESLint to browser and extension code, add Biome, and expose snapshot helpers for restart testing.

- Update README.md

- Update README.md

- Update README.md

- Add theme-aware architecture diagrams

Split the architecture image into light and dark variants and use a color-scheme-aware `<picture>` element in the README.

- Add architecture diagram to README

Replace the inline Mermaid architecture flowchart with a dedicated image in `.docs/architecture.png`.

- Update README.md

- Update README.md

- Update README.md

- Update README.md

- Update README.md

- Update README.md


## v1.2.5 - 2026-10-20

### Other

- Add security and site discovery metadata

Document vulnerability reporting and add security.txt, llms.txt, robots.txt, and a sitemap for Blink.


## v1.2.4 - 2026-10-20

### Other

- Improve mobile layout and overflow handling

Reorder the hero and secret card for smaller screens, compact the extension banner, and keep overflowing pills and badges scrollable to prevent page-width clipping.


## v1.2.3 - 2026-10-18

### Other

- Offer Pro upgrades for free-tier limits

Show an Upgrade to Pro action when users hit the free-tier daily cap, while keeping it hidden for rate limits that affect all plans.


## v1.2.2 - 2026-10-18

### Other

- Persist rate limits across graceful restarts

Snapshot and restore active rate-limiter entries so deploys preserve daily quotas and burst windows. Add a dedicated modal for 429 responses and document the new snapshot configuration.


## v1.2.1 - 2026-10-18

### Other

- Trust both reverse-proxy hops

Resolve client IPs correctly behind Cloudflare and nginx so IP-based rate limits and logs use the visitor address. Build the free-plan limit message from the configured maximum.

- Preserve secrets across graceful restarts

Snapshot pending encrypted secrets to persistent storage during graceful shutdown and restore them on startup. Document the snapshot configuration and restart behavior, and expand Beszel proxy, caching, and email setup guidance.


## v1.2.0 - 2026-10-18

### Other

- Log secret creation request source

Classify requests as extension, web, or unknown based on their Origin header and include the source in secret creation logs.

- Move Beszel hub off its default port

Publish the hub on localhost port 58988 instead of 8090 to avoid default-port scans, keeping the container's internal port unchanged. Update the agent URL, example environment, and setup and reverse-proxy documentation to match.

- Add Beszel monitoring stack and deployment

Add a separate Beszel hub and agent Compose stack, document its setup and updates, and provide a manual GitHub Actions workflow to deploy it independently of the Blink app.

- Add structured logging with pino, end to end

Replaces morgan/console.* with pino: every significant action (secret
created/viewed/destroyed, OTP sent/verified, license activate/deactivate,
OAuth login, rate limits, tampered sessions, misconfiguration) logs to both
the console and a rotating file under LOGS_DIR (daily, gzip, 14-day
retention) so nothing is lost across a container restart.

Access logging is scoped to /api/* only, so static assets and page loads
don't produce a line per file on every page view, while errors always log
regardless of path. Logged IP uses Express's trust-proxy-aware req.ip
instead of pino-http's default raw-socket address, which behind a reverse
proxy would otherwise be identical for every visitor.

flushLogs() is awaited before every intentional process.exit() (shutdown,
uncaughtException, unhandledRejection), since exiting right after a burst of
writes can otherwise lose them outright - verified by reproducing the loss
and then the fix with a real write-then-exit test.

Secrets, keys, OTP codes, and passphrases never reach a log line: call
sites only ever log specific chosen fields, backed by pino's redact config.

Also fixes two gaps left over from the GitHub sign-in work: missing
GITHUB_CLIENT_ID/SECRET/REDIRECT_URI in docker-compose.yml, and enables the
no-console ESLint rule so this can't silently regress.

- Add GitHub sign-in for Pro accounts

Support GitHub OAuth alongside Google, using verified email to share Pro accounts across providers and migrate existing license mappings. Update sign-in and privacy copy, and restrict service worker interception to same-origin requests with an offline cache fallback.

- Update style.css

- Add segmented OTP code input

Replace the single verification-code field with six digit boxes that support auto-advance, paste, autofill, and keyboard navigation. Adjust the Blink logo dimensions in email headers.

- Update about.html

- Document the Blink browser extension

Add extension features, store availability, architecture, and setup details to the README, and add a browser extension FAQ to the About page.


## v1.1.4 - 2026-10-17

### Other

- Refresh transactional email templates

Introduce shared branded headers, footers, and preheaders for verification and activity emails. Update both templates to a light theme with clearer status details and categorize their subject lines.


## v1.1.3 - 2026-10-14

### Features

- Add dismissible Chrome extension announcement banner


### Other

- Link Chrome extension listing on homepage and fix hero alignment

Chrome badge now links to the published Chrome Web Store listing with
its real logo and a NEW tag; Edge/Firefox stay disabled until published.
Also fixes the hero badge/link stretching to full width and the
subtitle's narrow text-wrap:balance wrapping.

- Add extension settings and themes

This commit adds persistent Blink extension settings stored in chrome.storage.sync, including selection bubble enablement, context-menu enablement, and default expiry. It introduces an options page for managing those settings, wires the background script to sync menu state instantly, and updates the selection bubble to respect the saved configuration. It also adds popup theming controls and a saved-theme initialization script, plus a privacy-policy navigation update and styling tweaks.


## v1.1.2 - 2026-10-11

### Other

- Add browser extension teaser

This change adds a new browser extension section to the homepage with soon-to-launch Chrome, Edge, and Firefox badges, along with styling for the new CTA and label treatment. It also tweaks a few layout styles to improve badge and hero alignment consistency.


## v1.1.1 - 2026-10-11

### Other

- Add Blink browser extension and privacy page

This commit introduces the Blink browser extension for creating shareable encrypted links directly from the browser, including selection-based and popup-based flows. It also adds the public privacy policy page and links it from the website footer, plus a small server route to serve the new page. The extension mirrors the site's encryption logic and is designed to keep the secret local before submitting to the Blink API.

- Harden cookies and document release flow

This patch hardens cookie parsing by using a null-prototype object to prevent prototype pollution from raw Cookie headers, and applies the read rate limiter to the /about and /view/:id pages. It also updates the README with the new light/dark theme, CI/CD workflow docs, and the project structure details for PWA assets and deployment.


## v1.1.0 - 2026-10-11

### Bug Fixes

- Polish header/footer brand marks and homepage layout details  - Recolor the Blink eye icon and MALTO footer mark via CSS mask so   they inherit the app's actual green/text tokens instead of their   baked-in PNG colors, keeping both in sync across light/dark mode - Default to light mode when no theme preference is stored, instead   of following the OS/browser's prefers-color-scheme - Keep the stat card's layout stable at any digit count by always   wrapping the sub-line onto its own row instead of relying on   overflow-triggered wrapping - Drop the homepage's duplicate "E2E Encrypted / View Once /   Auto-Expires" trust row now that the feature cards already say it

- Make owner-account button open Pro modal instead of disabling it

- Restore sign-out button visibility for owner accounts

- Hide sign-out button for owner accounts

- Improve sign-out button styling and dynamic modal title/label

- Satisfy eqeqeq lint rule in license validation check

- Move pricing to /about


### Chores

- Bump body-parser and js-yaml to patch known vulnerabilities

- Pass Pro licensing env vars to container


### Documentation

- Update about page with file sharing, Pro, and open source


### Features

- Serve images from assets.malto.icu, show app version, add release/deploy workflows

- Make mobile layout edge-to-edge with swipeable pricing cards

- Add Blink brand logo

- Show owner-account badge instead of a dead Remove Pro button

- Add OWNER_EMAILS allowlist for permanent Pro access

- Add sign-out button and shorten session lifetime to 7 days

- Blink Pro with Google OAuth-bound licensing

- Blink Pro with Lemon Squeezy licensing, passphrase, multi-view, and 25 MB files


### Other

- Use npm ci in release workflow

Switch the release workflow from `npm install` to `npm ci` to ensure a clean, reproducible dependency install using the lockfile during CI releases.

- Update proxy-addr to 2.0.8

Refresh the lockfile for the transitive proxy-addr dependency from 2.0.7 to 2.0.8, including the updated package metadata and the newly added OpenCollective funding entry.

- Add theme initialization and toggle functionality

- Introduced theme-init.js to set the initial theme based on localStorage.
- Added theme-toggle.js to handle theme switching between light and dark modes with appropriate SVG icons.
- Implemented accessibility features for the theme toggle button.

- Update package-lock.json

- Add QR code sharing for Pro users

Adds a Pro-only QR code sharing flow for generated links, including a QR button in the share UI and a scan modal that renders a QR code for the link. This also adds the qrcode-generator library and updates the pricing/about copy and styling to advertise the new feature.

- Add FREE_USAGE_RATE_LIMIT and enforce free-tier limit

Introduce FREE_USAGE_RATE_LIMIT (default 5/day) and enforce it for anonymous creators. Updates: .env.example adds the new variable; docker-compose.yml exposes it to the service; server.js creates a freeUsageLimiter (IP-bucketed) and returns 429 when the free daily quota is exceeded; public/index.html and public/about.html update UI copy to document the new per-day limits; test/api.test.js sets FREE_USAGE_RATE_LIMIT during tests.

- Show link fragment in emails & pro notify UI

Adds a PRO 'Notify me when viewed' UI control and includes the last 8 hex chars of a secret's UUID in OTP and view-notification emails so recipients can match emails to the correct share link. Implements an idFragment helper, passes the secret id into sendOTPEmail/sendViewNotification, and generates the id earlier in /api/secret so OTP emails can reference it. Uses only the tail (non-sensitive) fragment and includes small copy/layout tweaks.


## v1.0.0 - 2026-07-08

### Bug Fixes

- Apply Space Grotesk font to tabs, inputs, and buttons

- Improve file reveal meta text visibility

- Survive page refresh during OTP flow by caching K1 in sessionStorage

- Revert CSP beacon hashes — handled via Cloudflare Configuration Rule

- Allow Cloudflare beacon in CSP via domain + inline script hash

- Allow base64 padding in K1 regex — 32-byte key always ends with =

- Email template logo + title side by side with by MALTO text

- Email header matches site — logo + Blink + by MALTO side by side

- Center email OTP card content and add logo

- Add Cache-Control no-store to API responses

- Skip tab animation when clicking already active tab

- Fix logo-by spacing

- Move expiry toggle above divider


### Chores

- Relicense from MIT to AGPL-3.0

- Add MIT license and live demo link to README


### Documentation

- Update expiry references from fixed 48h to configurable 1-48h

-  docs: update README with K4, new arch diagram, four-factor key table

- Update README for key splitting architecture and K3 bindin

- Update README with email OTP, 48h TTL, and rate limiting


### Features

- Visual overhaul with atmosphere, contrast, and brand details

- Increase file sharing limit to 2 MB

- Warn before discarding uncoped link on tab switch or new secret

- Move install button to header on all pages with separator

- Add PWA support with install button and manifest-src CSP fix

- Add PWA support for desktop install

- Tests, security linting, toast errors, expiry options, byte counter, OG tags

- Add K4 server-side ciphertext encryption — mandatory fourth factor

- Add morgan request logging

- Add K3 HMAC binding to harden K2 at rest

- Secrets created counter on home page with count-up animation

- Email OTP with rate limiting and brute-force protection

- Email OTP verification for secret links


### Maintenance

- Remove em dashes from UI copy and add About link to footer


### Other

- Update README.md

- Fix stale text, add 48h to warn-box, remove dead CSS

- Add slide animation on tab switch

- Refactor code structure for improved readability and maintainability

- Initial Commit

- Initial commit


### Refactor

- Remove expiry feature and related code for simplification


