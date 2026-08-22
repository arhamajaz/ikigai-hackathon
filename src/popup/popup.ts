/**
 * SentinelEdge Popup HUD TypeScript Logic
 */

import { getStorageData, updateConfig, clearIncidents } from '../shared/storage';
import { TelemetryIncident } from '../shared/types';

document.addEventListener('DOMContentLoaded', async () => {
  const totalThreatsEl = document.getElementById('totalThreats') as HTMLElement;
  const incidentsListEl = document.getElementById('incidentsList') as HTMLElement;
  const toggleProtectionInput = document.getElementById('toggleProtection') as HTMLInputElement;
  const statusPillEl = document.getElementById('statusPill') as HTMLElement;
  const exportLogBtn = document.getElementById('exportLogBtn') as HTMLButtonElement;
  const clearLogBtn = document.getElementById('clearLogBtn') as HTMLButtonElement;

  async function renderHUD(): Promise<void> {
    const data = await getStorageData();
    const totalThreats = data.totalThreatsBlocked || 0;
    const incidents = data.incidentsLog || [];
    const config = data.config || { protectionEnabled: true, interceptionMode: 'silent_redact', whitelist: [] };

    totalThreatsEl.textContent = String(totalThreats);
    toggleProtectionInput.checked = config.protectionEnabled;

    if (config.protectionEnabled) {
      statusPillEl.textContent = 'ACTIVE';
      statusPillEl.className = 'status-pill active';
    } else {
      statusPillEl.textContent = 'DISABLED';
      statusPillEl.className = 'status-pill disabled';
    }

    if (incidents.length === 0) {
      incidentsListEl.innerHTML = '<div class="empty-state">No sensitive threats detected yet.</div>';
    } else {
      incidentsListEl.innerHTML = incidents.map((inc: TelemetryIncident) => {
        const timeStr = new Date(inc.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        return `
          <div class="incident-item">
            <span class="incident-domain">${inc.originUrl} (${timeStr})</span>
            <span class="incident-badge">${inc.threatsBlocked} Blocked</span>
          </div>
        `;
      }).join('');
    }
  }

  toggleProtectionInput.addEventListener('change', async () => {
    await updateConfig({ protectionEnabled: toggleProtectionInput.checked });
    renderHUD();
  });

  clearLogBtn.addEventListener('click', async () => {
    await clearIncidents();
    renderHUD();
  });

  exportLogBtn.addEventListener('click', async () => {
    const data = await getStorageData();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentineledge-audit-log-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  renderHUD();
});
