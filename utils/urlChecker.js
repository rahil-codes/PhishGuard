// utils/urlChecker.js
// URL and domain-based phishing detection heuristics

const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
  '.loan', '.work', '.date', '.racing', '.review', '.stream'
];

const TRUSTED_DOMAINS = [
  'google.com', 'facebook.com', 'microsoft.com', 'apple.com',
  'amazon.com', 'paypal.com', 'netflix.com', 'twitter.com',
  'instagram.com', 'linkedin.com', 'github.com', 'youtube.com',
  'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citibank.com'
];

// Common brand names that phishers impersonate
const BRAND_KEYWORDS = [
  'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
  'netflix', 'instagram', 'twitter', 'linkedin', 'ebay', 'walmart',
  'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
  'steam', 'discord', 'spotify', 'dropbox', 'adobe', 'yahoo'
];

/**
 * Extract hostname from a URL
 */
function getHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/**
 * Get the registered domain (e.g., "sub.example.com" → "example.com")
 */
function getRegisteredDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length >= 2) {
    return parts.slice(-2).join('.');
  }
  return hostname;
}

/**
 * Check if URL uses an IP address instead of a domain
 */
function isIPAddress(hostname) {
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Pattern = /^\[?[0-9a-fA-F:]+\]?$/;
  return ipv4Pattern.test(hostname) || ipv6Pattern.test(hostname);
}

/**
 * Count subdomains (e.g., "a.b.c.example.com" → 2 subdomains)
 */
function countSubdomains(hostname) {
  const parts = hostname.split('.');
  return Math.max(0, parts.length - 2);
}

/**
 * Detect lookalike / homograph attacks in domain
 * e.g., paypa1.com, g00gle.com, microsofft.com
 */
function detectLookalikeDomain(hostname) {
  const registeredDomain = getRegisteredDomain(hostname);
  const domainWithoutTld = registeredDomain.split('.')[0];

  for (const brand of BRAND_KEYWORDS) {
    if (domainWithoutTld === brand) continue; // exact match is fine

    // Check character substitutions (0→o, 1→l, @→a, etc.)
    const normalized = domainWithoutTld
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/\$/g, 's')
      .replace(/@/g, 'a')
      .replace(/vv/g, 'w');

    if (normalized === brand) {
      return { detected: true, brand, type: 'character_substitution' };
    }

    // Check if brand name is embedded in domain (e.g., paypal-secure.com)
    if (domainWithoutTld.includes(brand) && domainWithoutTld !== brand) {
      return { detected: true, brand, type: 'brand_embedded' };
    }

    // Levenshtein distance check for typosquatting
    if (brand.length > 4) {
      const distance = levenshteinDistance(domainWithoutTld, brand);
      if (distance === 1) {
        return { detected: true, brand, type: 'typosquat' };
      }
    }
  }

  return { detected: false };
}

/**
 * Simple Levenshtein distance implementation
 */
function levenshteinDistance(a, b) {
  const matrix = Array.from({ length: b.length + 1 }, (_, i) =>
    Array.from({ length: a.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b[i - 1] === a[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Check URL length and complexity
 */
function analyzeUrlComplexity(url) {
  const flags = [];
  if (url.length > 100) flags.push('very_long_url');
  if ((url.match(/-/g) || []).length >= 4) flags.push('many_hyphens');
  if ((url.match(/\./g) || []).length >= 5) flags.push('many_dots');
  if (url.includes('@')) flags.push('at_symbol_in_url');
  if (url.includes('//') && url.indexOf('//') !== url.indexOf('://')) {
    flags.push('double_slash');
  }
  return flags;
}

/**
 * Main URL analysis function
 * Returns a risk score (0-100) and list of findings
 */
function analyzeURL(url) {
  const findings = [];
  let score = 0;

  const hostname = getHostname(url);
  if (!hostname) return { score: 0, findings: ['invalid_url'], riskLevel: 'unknown' };

  const registeredDomain = getRegisteredDomain(hostname);

  // 1. Check if it's a trusted domain
  if (TRUSTED_DOMAINS.includes(registeredDomain)) {
    return { score: 0, findings: ['trusted_domain'], riskLevel: 'safe' };
  }

  // 2. IP address used as host
  if (isIPAddress(hostname)) {
    findings.push('ip_address_url');
    score += 30;
  }

  // 3. Suspicious TLD
  for (const tld of SUSPICIOUS_TLDS) {
    if (hostname.endsWith(tld)) {
      findings.push('suspicious_tld');
      score += 20;
      break;
    }
  }

  // 4. Too many subdomains
  const subdomainCount = countSubdomains(hostname);
  if (subdomainCount >= 3) {
    findings.push('excessive_subdomains');
    score += 15 * (subdomainCount - 2);
  }

  // 5. Lookalike domain detection
  const lookalike = detectLookalikeDomain(hostname);
  if (lookalike.detected) {
    findings.push(`lookalike_${lookalike.type}_${lookalike.brand}`);
    score += lookalike.type === 'character_substitution' ? 50 : 35;
  }

  // 6. URL complexity flags
  const complexityFlags = analyzeUrlComplexity(url);
  for (const flag of complexityFlags) {
    findings.push(flag);
    score += 10;
  }

  // 7. HTTPS check
  if (!url.startsWith('https://')) {
    findings.push('no_https');
    score += 15;
  }

  // Normalize score to 0-100
  score = Math.min(score, 100);

  const riskLevel = score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low';

  return { score, findings, riskLevel };
}

// Export for use in background.js and content.js
if (typeof module !== 'undefined') {
  module.exports = { analyzeURL, getHostname, getRegisteredDomain };
}
