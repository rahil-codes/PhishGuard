// background.js
// Service worker — handles URL analysis and coordinates with content script

importScripts('utils/urlChecker.js');

// ─── State ─────────────────────────────────────────────────────────────────

const tabResults = new Map(); // tabId → analysis result

// ─── Helpers ───────────────────────────────────────────────────────────────

function combineScores(urlResult, contentResult) {
  // Weighted average: URL analysis 40%, content analysis 60%
  const combined = Math.round(urlResult.score * 0.4 + contentResult.score * 0.6);
  const allFindings = [
    ...urlResult.findings.map(f => `[url] ${f}`),
    ...contentResult.findings.map(f => `[page] ${f}`)
  ];

  const riskLevel = combined >= 60 ? 'high' : combined >= 30 ? 'medium' : 'low';

  return {
    score: combined,
    riskLevel,
    findings: allFindings,
    urlAnalysis: urlResult,
    contentAnalysis: contentResult,
    timestamp: Date.now()
  };
}

function updateBadge(tabId, riskLevel) {
  const config = {
    high:    { text: '!',  color: '#e53e3e' },
    medium:  { text: '?',  color: '#dd6b20' },
    low:     { text: '✓',  color: '#38a169' },
    safe:    { text: '✓',  color: '#38a169' },
    unknown: { text: '~',  color: '#718096' }
  };

  const { text, color } = config[riskLevel] || config.unknown;

  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

// ─── Main Analysis Pipeline ────────────────────────────────────────────────

async function analyzeTab(tabId, url) {
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
    tabResults.set(tabId, { riskLevel: 'unknown', score: 0, findings: ['internal_page'] });
    updateBadge(tabId, 'unknown');
    return;
  }

  // Step 1: URL analysis (synchronous, fast)
  const urlResult = analyzeURL(url);

  // Store a preliminary result while we wait for content analysis
  tabResults.set(tabId, {
    ...urlResult,
    findings: urlResult.findings.map(f => `[url] ${f}`),
    pending: true
  });
  updateBadge(tabId, urlResult.riskLevel);

  // Step 2: Content analysis via content script
  try {
    const contentResponse = await chrome.tabs.sendMessage(tabId, { action: 'analyzeContent' });

    if (contentResponse?.success) {
      const combined = combineScores(urlResult, contentResponse.result);
      tabResults.set(tabId, combined);
      updateBadge(tabId, combined.riskLevel);
    }
  } catch (err) {
    // Content script may not be ready yet or page blocked injection
    console.warn('Content analysis failed:', err.message);
  }
}

// ─── Event Listeners ───────────────────────────────────────────────────────

// Trigger analysis when a page finishes loading
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return; // only main frame
  await analyzeTab(details.tabId, details.url);
});

// Also re-analyze on history state changes (SPAs)
chrome.webNavigation.onHistoryStateUpdated.addListener(async (details) => {
  if (details.frameId !== 0) return;
  await analyzeTab(details.tabId, details.url);
});

// Handle messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getResult') {
    const result = tabResults.get(message.tabId);
    sendResponse({ result: result || null });
  }

  if (message.action === 'reanalyze') {
    chrome.tabs.get(message.tabId, (tab) => {
      if (tab?.url) {
        analyzeTab(message.tabId, tab.url).then(() => {
          sendResponse({ success: true });
        });
      }
    });
    return true; // async
  }

  return false;
});

// Clean up state when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
});
