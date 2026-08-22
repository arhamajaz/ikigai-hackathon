/**
 * Storage Helper for SentinelEdge
 * Handles async getters/setters for chrome.storage.local
 */

import { ExtensionStorage, SentinelConfig } from './types';

const DEFAULT_CONFIG: SentinelConfig = {
  protectionEnabled: true,
  interceptionMode: 'silent_redact',
  whitelist: []
};

export async function getStorageData(): Promise<Partial<ExtensionStorage>> {
  return new Promise((resolve) => {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['totalThreatsBlocked', 'incidentsLog', 'config'], (result) => {
        resolve({
          totalThreatsBlocked: result.totalThreatsBlocked || 0,
          incidentsLog: result.incidentsLog || [],
          config: result.config || DEFAULT_CONFIG
        });
      });
    } else {
      resolve({
        totalThreatsBlocked: 0,
        incidentsLog: [],
        config: DEFAULT_CONFIG
      });
    }
  });
}

export async function updateConfig(newConfig: Partial<SentinelConfig>): Promise<SentinelConfig> {
  const current = await getStorageData();
  const updated: SentinelConfig = {
    ...DEFAULT_CONFIG,
    ...current.config,
    ...newConfig
  };

  return new Promise((resolve) => {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ config: updated }, () => {
        resolve(updated);
      });
    } else {
      resolve(updated);
    }
  });
}

export async function clearIncidents(): Promise<void> {
  return new Promise((resolve) => {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ totalThreatsBlocked: 0, incidentsLog: [] }, () => {
        resolve();
      });
    } else {
      resolve();
    }
  });
}
