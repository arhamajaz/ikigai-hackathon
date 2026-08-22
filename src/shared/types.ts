/**
 * Shared Type Definitions for SentinelEdge
 */

export interface TelemetryIncident {
  timestamp: string;
  threatsBlocked: number;
  originalLength: number;
  sanitizedLength: number;
  originUrl: string;
}

export interface WhitelistRule {
  id: string;
  pattern: string; // Keyword or regex string
  enabled: boolean;
  category?: string;
}

export interface SentinelConfig {
  protectionEnabled: boolean;
  interceptionMode: 'silent_redact' | 'interactive_modal';
  whitelist: WhitelistRule[];
}

export interface ExtensionStorage {
  totalThreatsBlocked: number;
  incidentsLog: TelemetryIncident[];
  config: SentinelConfig;
}
