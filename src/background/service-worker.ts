/**
 * SentinelEdge Background Service Worker
 */

console.log("[SentinelEdge] Background Service Worker initialized.");

// On extension install / update
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['totalThreatsBlocked', 'incidentsLog', 'config'], (data) => {
    if (data.totalThreatsBlocked === undefined) {
      chrome.storage.local.set({ totalThreatsBlocked: 0 });
    }
    if (!data.incidentsLog) {
      chrome.storage.local.set({ incidentsLog: [] });
    }
    if (!data.config) {
      chrome.storage.local.set({
        config: {
          protectionEnabled: true,
          interceptionMode: 'silent_redact',
          whitelist: []
        }
      });
    }
  });
});

// Update badge count dynamically when threats are blocked
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && changes.totalThreatsBlocked) {
    const newCount = changes.totalThreatsBlocked.newValue;
    if (newCount > 0) {
      chrome.action.setBadgeText({ text: String(newCount) });
      chrome.action.setBadgeBackgroundColor({ color: '#E11D48' }); // Neo-brutalist Rose red
    } else {
      chrome.action.setBadgeText({ text: '' });
    }
  }
});
