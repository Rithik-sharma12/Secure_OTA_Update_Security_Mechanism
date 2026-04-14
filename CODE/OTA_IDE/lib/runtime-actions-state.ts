import fs from 'node:fs/promises';
import path from 'node:path';
import { getLocalDatabaseDirectory } from '@/lib/local-database';
import { logger, errorTracker } from '@/lib/logger';

export type RuntimeSettings = {
  autoUpdateFirmware: boolean;
  emailNotifications: boolean;
  twoFactorAuth: boolean;
  deviceTelemetry: boolean;
  apiEndpoint: string;
  requestTimeoutSec: number;
  cacheSizeMb: number;
};

export type RuntimeReport = {
  id: string;
  title: string;
  type: string;
  format: 'PDF' | 'CSV' | 'JSON';
  status: 'generated' | 'generating' | 'failed';
  createdAt: string;
  sizeBytes: number;
  content: string;
};

export type RuntimeSimulatorState = {
  name: string;
  deviceType: string;
  firmwareVersion: string;
  status: 'running' | 'paused' | 'stopped';
  startedAt: string | null;
  updatedAt: string;
};

export type RuntimeGeneratedKey = {
  id: string;
  name: string;
  type: 'RSA' | 'ECDSA' | 'AES';
  keySize: number;
  createdAt: string;
  active: boolean;
  fingerprint: string;
};

export type RuntimeActionLogEntry = {
  id: string;
  action: string;
  message: string;
  createdAt: string;
  userId?: string;
};

export type RuntimeActionsState = {
  updatedAt: string;
  settings: RuntimeSettings;
  archivedReleaseIds: string[];
  reports: RuntimeReport[];
  simulator: RuntimeSimulatorState;
  tags: Array<{ version: string; notes: string; createdAt: string }>;
  generatedKeys: RuntimeGeneratedKey[];
  actionLog: RuntimeActionLogEntry[];
};

const stateFilePath = path.join(getLocalDatabaseDirectory(), 'runtime-actions-state.json');

const defaultState: RuntimeActionsState = {
  updatedAt: new Date().toISOString(),
  settings: {
    autoUpdateFirmware: true,
    emailNotifications: true,
    twoFactorAuth: false,
    deviceTelemetry: true,
    apiEndpoint: 'https://api.ota-ide.example.com/v1',
    requestTimeoutSec: 30,
    cacheSizeMb: 500,
  },
  archivedReleaseIds: [],
  reports: [],
  simulator: {
    name: 'Virtual ESP32 Device',
    deviceType: 'ESP32',
    firmwareVersion: 'v2.4.0',
    status: 'running',
    startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  tags: [],
  generatedKeys: [],
  actionLog: [],
};

function cloneDefaultState() {
  return JSON.parse(JSON.stringify(defaultState)) as RuntimeActionsState;
}

function normalizeState(raw: unknown): RuntimeActionsState {
  if (!raw || typeof raw !== 'object') {
    return cloneDefaultState();
  }

  const base = cloneDefaultState();
  const source = raw as Partial<RuntimeActionsState>;

  return {
    ...base,
    ...source,
    settings: {
      ...base.settings,
      ...(source.settings || {}),
    },
    archivedReleaseIds: Array.isArray(source.archivedReleaseIds) ? source.archivedReleaseIds.map(String) : [],
    reports: Array.isArray(source.reports) ? source.reports : [],
    simulator: {
      ...base.simulator,
      ...(source.simulator || {}),
    },
    tags: Array.isArray(source.tags) ? source.tags : [],
    generatedKeys: Array.isArray(source.generatedKeys) ? source.generatedKeys : [],
    actionLog: Array.isArray(source.actionLog) ? source.actionLog : [],
    updatedAt: typeof source.updatedAt === 'string' ? source.updatedAt : new Date().toISOString(),
  };
}

export async function getRuntimeActionsState() {
  try {
    const raw = await fs.readFile(stateFilePath, 'utf-8');
    return normalizeState(JSON.parse(raw));
  } catch (error: unknown) {
    logger.error('RuntimeActionsState', 'Failed to read or parse runtime actions state file, initializing default.', error);
    errorTracker.track(error, 'RuntimeActionsState:ReadStateFile');
    const state = cloneDefaultState();
    await saveRuntimeActionsState(state);
    return state;
  }
}

export async function saveRuntimeActionsState(state: RuntimeActionsState) {
  const normalized = normalizeState(state);
  normalized.updatedAt = new Date().toISOString();
  try {
    await fs.writeFile(stateFilePath, JSON.stringify(normalized, null, 2), 'utf-8');
    return normalized;
  } catch (error: unknown) {
    logger.error('RuntimeActionsState', 'Failed to write runtime actions state file.', error);
    errorTracker.track(error, 'RuntimeActionsState:WriteStateFile');
    throw error; // Re-throw to indicate save failure
  }
}

export async function updateRuntimeActionsState(
  updater: (current: RuntimeActionsState) => RuntimeActionsState
) {
  const current = await getRuntimeActionsState();
  const next = updater(current);
  return saveRuntimeActionsState(next);
}

export function getDefaultRuntimeSettings() {
  return cloneDefaultState().settings;
}
