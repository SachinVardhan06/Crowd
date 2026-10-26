# GKB Bug Bounty — Manual Hunting Playbook

Program: Graubündner Kantonalbank (GKB). Budget CHF 10'000, max CHF 5'000, avg CHF 790.

## Ground rules (read before every session)

- **Manual testing only.** No scanners, fuzzers, brute-force, automated crawling, or
  scripts that hit GKB hosts. Findings from automated testing are not rewarded and can
  get you excluded. Burp: Proxy + Repeater are fine; Intruder/Scanner/active crawl are not.
- **Out of scope:** `onboarding.gkb.ch`. Re-check the program page before each session.
  The scope list and the date it was last updated can change.
- Use **only your own accounts / test data**. When you prove an IDOR or data exposure,
  stop at the smallest proof that shows it (one record, redact it). Don't pull more data.
- No DoS and no destructive actions. Don't fire payloads at the VPN or mail appliances
  that could crash them.
- Follow the platform's Standards + T&C (confidentiality, no disclosure).

## Where the money is

| Tier | Assets | Critical | High |
|---|---|---|---|
| High risk | iOS app, Android app, `gioia.portal.gkb.ch`, `securemail.gkb.ch`, `vpn2corp.gkb.ch`, `hub.business-banking.gkb.ch` | 2560–5000 | 640–2560 |
| Medium risk | `www.gkb.ch`, `makoshare.gkb.ch` | 512–1000 | 200–512 |
| Low risk | `*.gkb.ch` (everything else, minus out of scope) | 256–500 | 100–256 |

A High on a high-risk asset pays more than a Critical on a low-risk one. Spend most of
your time on the first row.

## Phase 0 — Passive recon (no traffic to GKB)

These sources are third-party, so querying them never touches GKB infrastructure:

- Certificate transparency: `https://crt.sh/?q=%25.gkb.ch` (in the browser). Note every
  hostname. Mark anything new against the scope table above.
- Passive DNS / historic records (SecurityTrails, VirusTotal, DNSDumpster web UI).
- Wayback Machine: `https://web.archive.org/web/*/gkb.ch/*` lists old endpoints, JS files,
  and API paths for www and the portals.
- GitHub/GitLab code search for `gkb.ch`. Look for leaked configs, API hosts, and
  test credentials in vendor or agency repos.
- Public app metadata: store listings, app version history, privacy labels (which
  SDKs/trackers are bundled).

Record results in `notes.md`. **Subdomain takeover check:** for each CT hostname, look up
its CNAME manually (`dig CNAME host`). A CNAME pointing at an unclaimed cloud resource
(Azure, AWS S3/CloudFront, Heroku, GitHub Pages, etc.) is a classic finding. Even on
`*.gkb.ch` it's often rated High because of the bank's domain trust.

## Phase 1 — Mobile apps (high tier)

### Static analysis (local, no traffic to GKB)

Before you start, check that the T&C allow reverse engineering. Most programs that list
the app as an asset do.

- Get the APK (`com.gkb.mobilebanking.production.release`) and decompile with `jadx`.
  For iOS, use a decrypted IPA from your own jailbroken device.
- Grep for: API base URLs (they may reveal **staging/UAT hosts** under `*.gkb.ch`),
  API keys, client secrets, Firebase/Google config, hardcoded feature flags.
- `AndroidManifest.xml`: exported activities/services/receivers/providers without
  permissions; deep link / app link intent filters (`<data android:scheme=...>`).
- WebViews: `setJavaScriptEnabled`, `addJavascriptInterface`,
  `setAllowFileAccess`/`setAllowUniversalAccessFromFileURLs`, and whether deep-link
  params get loaded into a WebView (→ open redirect / JS-bridge abuse).
- `network_security_config.xml`: cleartext allowed? user CAs trusted? pinning config?
- Local storage: SharedPreferences / NSUserDefaults / SQLite for tokens or PII
  stored in plaintext.
- Biometric login: is it just a boolean check (`onAuthenticationSucceeded` → proceed),
  or is it bound to a Keystore/Secure Enclave key with `setUserAuthenticationRequired`?
  A boolean-only check can be bypassed on a rooted device. Impact is limited because
  the attacker needs the device, but the finding is real.

### Dynamic / API (manual, via Burp Proxy + Repeater)

- **Authorization (IDOR):** account IDs, IBANs, portfolio IDs, document/statement IDs,
  card IDs, message IDs. Swap them between two of your own accounts. Check both read
  and write endpoints.
- **Payment flow tampering:** change amount, currency, debit account, or beneficiary
  *after* the confirmation/2FA step. Replay a signed/confirmed request with altered
  fields. Is the signature bound to the transaction data?
- **2FA / transaction signing:** skip the step (call the "execute" endpoint directly),
  reuse an old OTP/approval, and confirm transaction A with approval for transaction B.
- **QR-bill (Swiss QR-Rechnung) scanning:** craft QR codes with oversized fields,
  unusual characters in creditor/reference fields, and a mismatched IBAN vs. QR-IBAN.
  Does the app or backend validate, or does the payload reach a WebView/HTML render?
- **Session handling:** is the token still valid after logout? After a password change?
  Does device binding hold if you move the session token to another device?
- **Deep links:** trigger them with `adb shell am start -d "<scheme>://..."` against
  your own device. Look for unvalidated redirects, auto-actions without confirmation,
  and token leakage.

## Phase 2 — Web assets (high tier)

For each host, first spend 30 min **browsing manually** with Burp Proxy on. Map the
login, registration, password reset, profile, upload, and export features. Note the
product/vendor in use (page footers, cookie names, JS file names, `/robots.txt`).
When you know the product, read its public advisories. Only report a version-based
issue if you can **demonstrate** impact safely. "Version X is outdated" alone rarely pays.

### `hub.business-banking.gkb.ch`

Usually the richest target: multi-user, multi-role, money movement.

- **Role matrix:** get (or ask the program for) a corporate test setup with several
  users: admin, signer, viewer. Replay every admin/signer request with the viewer's
  session.
- **Collective signature (Kollektivunterschrift) bypass:** can one signer complete
  a payment that needs two signatures? Approve twice with the same user? Edit a payment
  after the first signature without resetting approvals?
- **Payment file upload (ISO 20022 `pain.001` XML, maybe CSV):**
  - XXE: does the parser resolve external entities? Use an out-of-band callback to a
    host you control, and **never** read real system files beyond proof.
  - Oversized/malformed files are DoS, so leave those out of scope.
  - Mismatched debtor account in the file vs. the account you're allowed to use.
- **Exports/statements:** IDOR on report/download IDs; CSV/formula injection (often
  rated low or informational).
- **User management:** can an admin of company A invite into or modify users of
  company B? Mass assignment on user-update requests (add a `role` or `limits` field).

### `gioia.portal.gkb.ch`

- Work out what the portal does and who uses it (customer, partner, or employee?).
  The attack surface depends on that.
- Standard portal checklist: password reset (host header injection in reset links,
  token reuse/expiry, user enumeration), registration (claiming another person's
  identifier), IDOR on any object IDs, file upload (type validation, stored XSS via SVG/HTML,
  path traversal in filenames), stored XSS in any field that someone else views.

### `securemail.gkb.ch`

- Secure mail gateways let external recipients register and read mail. Test:
  - Recipient registration / first login: can you register for **another**
    recipient's address, or take over an account via the reset flow?
  - Mail viewer: stored XSS / HTML injection in subject, body, or attachment names
    (send to yourself).
  - Attachment download: IDOR on attachment/message IDs.
  - Open redirect on login/logout `returnUrl`-style params.
- Identify the vendor product and check its advisory history.

### `vpn2corp.gkb.ch`

- **Be careful here.** This is corporate access infrastructure.
  - No credential guessing at all. Even "a few tries" counts as brute force.
  - Fingerprint the product/version manually from the login page.
  - If a known pre-auth vulnerability matches, use only a **non-destructive check**
    (e.g. a version endpoint, a harmless read). If in doubt, report the indicator and
    ask the program before you go further.
  - Anything that could crash or lock out the appliance is off-limits.

## Phase 3 — Medium tier

### `www.gkb.ch`

- Contact/appointment forms, calculators (mortgage, pension 3a), search: reflected/stored
  XSS, open redirects, SSRF in any "fetch URL" feature, and header injection in email forms.
- Look for old CMS paths from the Wayback Machine (admin panels, preview endpoints,
  exposed `/api/` routes).

### `makoshare.gkb.ch`

- File-sharing access control: guessable or predictable share links, links that keep
  working after expiry/revocation, and IDOR on file/folder IDs.
- Upload: stored XSS via HTML/SVG served inline, content-type sniffing.

## Phase 4 — `*.gkb.ch` wildcard

- Work through the Phase 0 hostname list **manually**: open each one in the browser
  and note what it is. Look for:
  - Dangling CNAMEs (takeover).
  - Exposed staging/UAT/test hosts (these often have weaker auth).
  - Default vendor pages, exposed admin consoles, directory listings.
  - Misconfigured CORS (`Access-Control-Allow-Origin` reflecting your origin **with**
    credentials) on API hosts. A real finding needs a PoC that reads data.

## Report checklist

- [ ] Asset is in scope (and not `onboarding.gkb.ch`)
- [ ] Found manually; you can describe the exact manual steps
- [ ] Minimal PoC; any customer data you touched is redacted
- [ ] Clear impact statement (what an attacker gains, preconditions)
- [ ] Severity claim matches the tier table
- [ ] Remediation suggestion
- [ ] Screenshots / Burp request–response pairs attached
