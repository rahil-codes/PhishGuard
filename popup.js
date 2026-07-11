// popup.js
// Drives the PhishGuard popup UI

const RISK_CONFIG = {
  high:    { icon: '⚠️', label: 'HIGH RISK',    class: 'high' },
  medium:  { icon: '⚡', label: 'SUSPICIOUS',   class: 'medium' },
  low:     { icon: '✅', label: 'LOOKS SAFE',   class: 'safe' },
  safe:    { icon: '✅', label: 'TRUSTED SITE', class: 'safe' },
  unknown: { icon: '❓', label: 'UNKNOWN',      class: 'unknown' }
};

function formatFinding(raw) {
  return raw
    .replace(/^\[(url|page)\] /, '')
    .replace(/_/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .toLowerCase();
}

function getFindingType(raw) {
  if (raw.startsWith('[url]')) return 'url';
  if (raw.startsWith('[page]')) return 'page';
  return 'safe';
}

function renderResult(result, url) {
  const config = RISK_CONFIG[result.riskLevel] || RISK_CONFIG.unknown;
  const score = result.score ?? 0;
  const findings = result.findings || [];

  // Filter out 'trusted_domain' single safe message as a finding
  const displayFindings = findings.filter(f => !f.includes('trusted_domain') && !f.includes('internal_page'));

  const findingsHtml = displayFindings.length === 0
    ? `<div style="color: var(--safe); font-size: 12px; padding: 4px 0;">No suspicious signals found</div>`
    : displayFindings.map(f => `
        <div class="finding-item">
          <div class="finding-dot ${getFindingType(f)}"></div>
          <span class="finding-text">${formatFinding(f)}</span>
        </div>
      `).join('');

  const shortUrl = url ? url.replace(/^https?:\/\//, '').slice(0, 55) + (url.length > 60 ? '…' : '') : 'Unknown URL';

  document.getElementById('main-content').innerHTML = `
    <div class="risk-card">
      <div class="risk-header">
        <div class="risk-icon ${config.class}">${config.icon}</div>
        <div>
          <div class="risk-label">Risk Level</div>
          <div class="risk-value ${config.class}">${config.label}</div>
        </div>
      </div>
      <div class="score-bar-wrap">
        <div class="score-bar-track">
          <div class="score-bar-fill ${config.class}" id="score-fill" style="width: 0%"></div>
        </div>
        <div class="score-meta">
          <span>Risk Score</span>
          <span>${score}/100</span>
        </div>
      </div>
    </div>

    <div class="url-strip" title="${url || ''}">${shortUrl}</div>

    <div class="findings-section">
      <div class="section-label">Signals Detected</div>
      <div class="findings-list">${findingsHtml}</div>
    </div>

    ${result.pending ? `
    <div style="padding: 0 16px 8px;">
      <div class="loading-text">
        <span class="pending-dot"></span>
        Deep scan in progress…
      </div>
    </div>` : ''}
  `;

  // Animate score bar after render
  requestAnimationFrame(() => {
    const fill = document.getElementById('score-fill');
    if (fill) fill.style.width = score + '%';
  });
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  // Request cached result from background
  chrome.runtime.sendMessage({ action: 'getResult', tabId: tab.id }, (res) => {
    if (res?.result) {
      renderResult(res.result, tab.url);
    } else {
      // No result yet — trigger analysis
      chrome.runtime.sendMessage({ action: 'reanalyze', tabId: tab.id }, () => {
        setTimeout(() => {
          chrome.runtime.sendMessage({ action: 'getResult', tabId: tab.id }, (r) => {
            if (r?.result) renderResult(r.result, tab.url);
          });
        }, 1200);
      });
    }
  });

  // Re-scan button
  document.getElementById('btn-reanalyze').addEventListener('click', () => {
    document.getElementById('main-content').innerHTML = `
      <div class="empty-state">
        <div class="loading-text" style="justify-content:center;">
          <span class="pending-dot"></span> Scanning…
        </div>
      </div>
    `;
    chrome.runtime.sendMessage({ action: 'reanalyze', tabId: tab.id }, () => {
      setTimeout(() => {
        chrome.runtime.sendMessage({ action: 'getResult', tabId: tab.id }, (r) => {
          if (r?.result) renderResult(r.result, tab.url);
        });
      }, 1500);
    });
  });

  // Report button
  document.getElementById('btn-report').addEventListener('click', () => {
    const reportUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(tab.url)}`;
    chrome.tabs.create({ url: reportUrl });
  });
}

document.addEventListener('DOMContentLoaded', init);
