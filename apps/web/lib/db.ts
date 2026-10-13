import fs from 'node:fs';
import path from 'node:path';
import Datastore from 'nedb-promises';

type StoreBaseRecord = {
  _id: string;
  createdAt: Date;
  updatedAt: Date;
};

export type WebhookStatus = 'PENDING' | 'COMPLETED' | 'FAILED';

export interface WebhookRecord {
  _id?: string;
  eventId: string;
  type: string;
  payload: unknown;
  status: WebhookStatus;
  attempts: number;
  nextRetryAt?: Date;
  completedAt?: Date;
  failedAt?: Date;
  error?: string;
  lastError?: string;
  createdAt?: Date;
  updatedAt?: Date;
}

const dataDirectory = path.join(process.cwd(), '.data');
fs.mkdirSync(dataDirectory, { recursive: true });

function createStore<T>(fileName: string) {
  return Datastore.create({
    filename: path.join(dataDirectory, fileName),
    timestampData: true,
  }) as Datastore<StoreBaseRecord & T>;
}

// Data management stores
export const accountsDb = createStore<Record<string, unknown>>('accounts.db');
export const transactionsDb = createStore<Record<string, unknown>>('transactions.db');
export const auditDb = createStore<Record<string, unknown>>('audit.db');
export const webhooksDb = createStore<WebhookRecord>('webhooks.db');

let initialized = false;

export async function initializeWorkflowDatabases() {
  if (initialized) {
    return;
  }

  await Promise.all([
    accountsDb.load(),
    transactionsDb.load(),
    auditDb.load(),
    webhooksDb.load(),
  ]);

  await Promise.all([
    transactionsDb.ensureIndex({ fieldName: 'idempotencyKey', unique: true }),
    accountsDb.ensureIndex({ fieldName: 'userId' }),
    webhooksDb.ensureIndex({ fieldName: 'status' }),
    webhooksDb.ensureIndex({ fieldName: 'eventId', unique: true }),
    webhooksDb.ensureIndex({ fieldName: 'nextRetryAt' }),
  ]);

  initialized = true;
}