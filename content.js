// content.js
// Analyzes page DOM content for phishing signals

(function () {
  'use strict';

  // ─── Phishing Content Signals ─────────────────────────────────────────────

  const URGENCY_PATTERNS = [
    /your account (has been|will be) (suspended|locked|disabled|closed)/i,
    /verify your (account|identity|information) (immediately|now|urgently)/i,
    /unusual (activity|sign.?in|login) detected/i,
    /confirm your (password|credentials|details) (now|immediately)/i,
    /you have been selected/i,
    /limited time offer/i,
    /act (now|immediately|fast)/i,
    /expires? (in|within) \d+ (hour|minute|day)/i,
    /account (will be|has been) (terminated|suspended|blocked)/i,
    /security (alert|warning|notice)/i
  ];

  const SENSITIVE_FIELD_TYPES = [
    'password', 'ssn', 'social_security', 'credit_card', 'card_number',
    'cvv', 'cvc', 'pin', 'tax_id', 'passport', 'drivers_license'
  ];

  // ─── Analysis Functions ────────────────────────────────────────────────────

  /**
   * Detect login/credential forms on the page
   */
  function detectLoginForms() {
    const forms = document.querySelectorAll('form');
    const inputs = document.querySelectorAll('input');
    const findings = [];

    let hasPasswordField = false;
    let hasEmailOrUsernameField = false;
    let hasSensitiveField = false;

    inputs.forEach(input => {
      const type = (input.type || '').toLowerCase();
      const name = (input.name || '').toLowerCase();
      const id = (input.id || '').toLowerCase();
      const placeholder = (input.placeholder || '').toLowerCase();
      const autocomplete = (input.autocomplete || '').toLowerCase();
      const combined = `${name} ${id} ${placeholder} ${autocomplete}`;

      if (type === 'password') hasPasswordField = true;
      if (type === 'email' || combined.includes('email') || combined.includes('username') || combined.includes('user')) {
        hasEmailOrUsernameField = true;
      }

      for (const sensitive of SENSITIVE_FIELD_TYPES) {
        if (combined.includes(sensitive)) {
          hasSensitiveField = true;
          findings.push(`sensitive_field_${sensitive}`);
          break;
        }
      }
    });

    if (hasPasswordField) findings.push('has_password_field');
    if (hasPasswordField && hasEmailOrUsernameField) findings.push('login_form_detected');
    if (hasSensitiveField) findings.push('sensitive_data_form');

    return { findings, formCount: forms.length, inputCount: inputs.length };
  }

  /**
   * Detect urgency/fear language in visible page text
   */
  function detectUrgencyLanguage() {
    const bodyText = document.body?.innerText || '';
    const findings = [];

    for (const pattern of URGENCY_PATTERNS) {
      if (pattern.test(bodyText)) {
        findings.push('urgency_language');
        break; // one flag is enough
      }
    }

    return findings;
  }

  /**
   * Detect brand impersonation: page claims to be a brand but URL doesn't match
   */
  function detectBrandMismatch() {
    const findings = [];
    const hostname = window.location.hostname.toLowerCase();

    const BRANDS = {
      'paypal': ['paypal.com'],
      'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.in'],
      'apple': ['apple.com', 'icloud.com'],
      'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
      'google': ['google.com', 'gmail.com', 'accounts.google.com'],
      'facebook': ['facebook.com', 'fb.com'],
      'netflix': ['netflix.com'],
      'instagram': ['instagram.com'],
      'twitter': ['twitter.com', 'x.com'],
      'chase': ['chase.com'],
      'wellsfargo': ['wellsfargo.com'],
      'bankofamerica': ['bankofamerica.com'],
    };

    const titleAndBody = (
      (document.title || '') + ' ' +
      (document.querySelector('h1')?.innerText || '') + ' ' +
      (document.querySelector('h2')?.innerText || '')
    ).toLowerCase();

    for (const [brand, trustedDomains] of Object.entries(BRANDS)) {
      const claimsToBeThisBrand = titleAndBody.includes(brand);
      const isActuallyThisBrand = trustedDomains.some(d => hostname.endsWith(d));

      if (claimsToBeThisBrand && !isActuallyThisBrand) {
        findings.push(`brand_mismatch_${brand}`);
      }
    }

    return findings;
  }

  /**
   * Detect hidden iframes (common in phishing for credential harvesting)
   */
  function detectHiddenIframes() {
    const iframes = document.querySelectorAll('iframe');
    const findings = [];
    let hiddenCount = 0;

    iframes.forEach(iframe => {
      const style = window.getComputedStyle(iframe);
      const isHidden =
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        style.opacity === '0' ||
        parseInt(style.width) < 5 ||
        parseInt(style.height) < 5;

      if (isHidden) hiddenCount++;
    });

    if (hiddenCount > 0) {
      findings.push(`hidden_iframes_${hiddenCount}`);
    }

    return findings;
  }

  /**
   * Check for favicon mismatch: favicon from a well-known brand domain
   * but current URL is different
   */
  function detectFaviconMismatch() {
    const findings = [];
    const currentHost = window.location.hostname.toLowerCase();

    const faviconLinks = document.querySelectorAll('link[rel*="icon"]');
    faviconLinks.forEach(link => {
      const href = link.href || '';
      try {
        const faviconHost = new URL(href).hostname.toLowerCase();
        if (faviconHost && faviconHost !== currentHost && !faviconHost.includes(currentHost)) {
          findings.push('favicon_from_external_domain');
        }
      } catch {}
    });

    return findings;
  }

  /**
   * Check if external scripts are loaded from suspicious domains
   */
  function detectSuspiciousScripts() {
    const findings = [];
    const currentHost = window.location.hostname.toLowerCase();
    const scripts = document.querySelectorAll('script[src]');
    let externalCount = 0;

    scripts.forEach(script => {
      try {
        const scriptHost = new URL(script.src).hostname.toLowerCase();
        if (scriptHost !== currentHost) externalCount++;
      } catch {}
    });

    if (externalCount > 10) {
      findings.push('many_external_scripts');
    }

    return findings;
  }

  // ─── Main Content Analysis ─────────────────────────────────────────────────

  function analyzePageContent() {
    const allFindings = [];
    let score = 0;

    const formAnalysis = detectLoginForms();
    allFindings.push(...formAnalysis.findings);

    const urgencyFindings = detectUrgencyLanguage();
    allFindings.push(...urgencyFindings);

    const brandFindings = detectBrandMismatch();
    allFindings.push(...brandFindings);

    const iframeFindings = detectHiddenIframes();
    allFindings.push(...iframeFindings);

    const faviconFindings = detectFaviconMismatch();
    allFindings.push(...faviconFindings);

    const scriptFindings = detectSuspiciousScripts();
    allFindings.push(...scriptFindings);

    // Score based on findings
    if (allFindings.includes('login_form_detected')) score += 10;
    if (allFindings.includes('sensitive_data_form')) score += 20;
    if (allFindings.includes('urgency_language')) score += 25;
    if (brandFindings.length > 0) score += 40;
    if (iframeFindings.length > 0) score += 20;
    if (allFindings.includes('favicon_from_external_domain')) score += 15;
    if (allFindings.includes('many_external_scripts')) score += 10;

    score = Math.min(score, 100);

    return {
      score,
      findings: allFindings,
      riskLevel: score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low',
      meta: {
        formCount: formAnalysis.formCount,
        inputCount: formAnalysis.inputCount,
        url: window.location.href,
        title: document.title
      }
    };
  }

  // ─── Message Listener ──────────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'analyzeContent') {
      try {
        const result = analyzePageContent();
        sendResponse({ success: true, result });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    }
    return true; // keep message channel open for async
  });

})();
