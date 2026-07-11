# PhishGuard  — Phishing Detection Chrome Extension

A real-time phishing and malicious website detector built as a Chrome Extension using Manifest V3. PhishGuard analyses both the URL structure and live page content to calculate a danger score and present an instant visual risk rating.

---

##  Live Demo
Install locally from source — see setup instructions below.

---

## Overview
PhishGuard runs silently in the background on every page you visit. It performs a two-layer analysis:
1. **URL Analysis** — inspects the domain, TLD, subdomains, and URL structure for phishing signals
2. **Content Analysis** — scans the live DOM for phishing indicators like credential forms, urgency language, brand impersonation, and hidden iframes

Both scores are combined using a weighted average (40% URL + 60% content) to produce a final risk score from 0–100, displayed as a badge on the extension icon and a detailed popup UI.

---

## Features

###  URL Analysis Engine (`urlChecker.js`)
-  Trusted domain whitelist (Google, Amazon, PayPal, GitHub, etc.)
-  Suspicious TLD detection (`.tk`, `.ml`, `.xyz`, `.click`, `.loan`, etc.)
-  IP address used as hostname detection
-  Excessive subdomain detection
-  Lookalike / homograph attack detection:
  - Character substitution (`paypa1.com`, `g00gle.com`)
  - Brand name embedded in domain (`paypal-secure-login.com`)
  - Typosquatting via Levenshtein distance algorithm (`micosoft.com`)
-  URL complexity analysis (length, hyphens, dots, `@` symbols)
-  HTTPS enforcement check

###  Content Analysis Engine (`content.js`)
-  Login and credential form detection
-  Sensitive field detection (SSN, CVV, passport, PIN, etc.)
-  Urgency and fear language detection (10 regex patterns)
-  Brand impersonation detection — cross-checks page title/headings vs actual URL for 12 major brands
-  Hidden iframe detection (credential harvesting technique)
-  Favicon mismatch detection (favicon from external domain)
-  Suspicious external script detection

###  Popup UI (`popup.html` + `popup.js`)
- Dark-themed, minimal UI with real-time risk display
- Animated risk score progress bar
- Color-coded risk levels: 🟢 Safe / 🟡 Suspicious / 🔴 High Risk
- Scrollable findings list with URL and page signal tags
- Rescan button for manual re-analysis
- Direct report button linking to Google Safe Browsing

###  Background Service Worker (`background.js`)
- Runs analysis on every page load and SPA navigation
- Maintains per-tab result cache using `Map`
- Updates extension badge icon with risk level in real time
- Handles popup ↔ background messaging

---

## Tech Stack
- **JavaScript (ES6+)** — vanilla JS, no frameworks
- **Chrome Extension Manifest V3** — service worker architecture
- **Chrome APIs** — `webNavigation`, `tabs`, `scripting`, `runtime`, `action`
- **DOM API** — live page content inspection via content script
- **Custom Algorithms** — Levenshtein distance, weighted score combination

---

## Project Structure
```
phishguard/
├── manifest.json          # Extension config (MV3)
├── background.js          # Service worker — analysis pipeline & badge updates
├── content.js             # DOM content analysis injected into every page
├── popup.html             # Extension popup UI
├── popup.js               # Popup logic — renders results, handles buttons
├── utils/
│   └── urlChecker.js      # URL heuristics engine (lookalike, TLD, complexity)
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## How Risk Score is Calculated

| Signal | Score Added |
|---|---|
| IP address as hostname | +30 |
| Suspicious TLD | +20 |
| Excessive subdomains | +15 per extra subdomain |
| Character substitution (e.g. paypa1.com) | +50 |
| Brand embedded in domain | +35 |
| Typosquatting (Levenshtein = 1) | +35 |
| No HTTPS | +15 |
| Very long URL (>100 chars) | +10 |
| Urgency language detected | +25 |
| Brand impersonation on page | +40 |
| Sensitive form fields | +20 |
| Login form detected | +10 |
| Hidden iframes | +20 |
| Favicon from external domain | +15 |

**Final Score = URL Score × 0.4 + Content Score × 0.6** (capped at 100)

| Score Range | Risk Level |
|---|---|
| 0–29 | 🟢 Low / Safe |
| 30–59 | 🟡 Medium / Suspicious |
| 60–100 | 🔴 High Risk |

---

## Installation (Local)

1. Clone the repository
```bash
git clone https://github.com/rahil-codes/phishguard.git
```

2. Open Chrome and go to:
```
chrome://extensions/
```

3. Enable **Developer Mode** (toggle in top right)

4. Click **"Load unpacked"**

5. Select the `phishguard/` folder

6. The PhishGuard icon appears in your Chrome toolbar — visit any website to see it in action

---

## What I Learned
- Chrome Extension Manifest V3 architecture — service workers, content scripts, and messaging
- Building multi-layer security analysis pipelines in JavaScript
- Implementing the Levenshtein distance algorithm for typosquatting detection
- DOM inspection techniques for phishing signal detection
- Chrome APIs — `webNavigation`, `tabs`, `scripting`, `runtime.onMessage`
- Designing a weighted scoring system combining multiple signals
- Building dark-themed, animated UI with vanilla CSS

---

## Author
**Rahil** — [github.com/rahil-codes](https://github.com/rahil-codes)

---

## ⚠️ Disclaimer
PhishGuard is a heuristic-based tool and may produce false positives or miss sophisticated phishing attacks. Always exercise caution online. This project is built for educational purposes.
