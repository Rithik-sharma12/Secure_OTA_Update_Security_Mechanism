import fs from 'node:fs';
import path from 'node:path';
import Datastore from 'nedb-promises';

type Timestamp = Date | string;
type StoreBaseRecord = {
  _id: string;
  createdAt: Date;
  updatedAt: Date;
};

export interface UserRecord {
  _id?: string;
  username: string;
  passwordHash: string;
  role: 'admin' | 'operator' | 'viewer';
  isActive: boolean;
  lastLoginAt?: Timestamp;
  createdAt?: Timestamp;
  updatedAt?: Timestamp;
}

export interface SessionRecord {
  _id?: string;
  tokenHash: string;
  userId: string;
  expiresAt: number;
  revoked: boolean;
  createdAt?: Timestamp;
  updatedAt?: Timestamp;
}

export interface UploadRecord {
  _id?: string;
  jobId: string;
  userId: string;
  filePath: string;
  fileName: string;
  fileHash: string;
  boardType: string;
  fqbn: string;
  comPort: string;
  baudRate: string;
  status: 'queued' | 'compiling' | 'uploading' | 'success' | 'failed';
  progress: number;
  errorMessage?: string;
  startedAt: string;
  endedAt?: string;
  createdAt?: Timestamp;
  updatedAt?: Timestamp;
}

export interface UploadLogRecord {
  _id?: string;
  jobId: string;
  sequence: number;
  level: 'info' | 'warning' | 'error' | 'success';
  message: string;
  loggedAt: string;
  createdAt?: Timestamp;
  updatedAt?: Timestamp;
}

export interface ApiLogRecord {
  _id?: string;
  route: string;
  method: string;
  statusCode: number;
  durationMs: number;
  userId?: string;
  errorMessage?: string;
  createdAt?: Timestamp;
  updatedAt?: Timestamp;
}

const dbDirectory = path.resolve(process.cwd(), process.env.OTA_LOCAL_DB_DIR || '.local-db');
fs.mkdirSync(dbDirectory, { recursive: true });

function createStore<T>(fileName: string) {
  return Datastore.create({
    filename: path.join(dbDirectory, fileName),
    timestampData: true,
  }) as Datastore<StoreBaseRecord & T>;
}

export const usersStore = createStore<UserRecord>('users.db');
export const sessionsStore = createStore<SessionRecord>('sessions.db');
export const uploadsStore = createStore<UploadRecord>('uploads.db');
export const uploadLogsStore = createStore<UploadLogRecord>('upload-logs.db');
export const apiLogsStore = createStore<ApiLogRecord>('api-logs.db');

let initialized = false;

export async function initializeLocalDatabase() {
  if (initialized) {
    return;
  }

  await Promise.all([
    usersStore.load(),
    sessionsStore.load(),
    uploadsStore.load(),
    uploadLogsStore.load(),
    apiLogsStore.load(),
  ]);

  await usersStore.ensureIndex({ fieldName: 'username', unique: true });
  await sessionsStore.ensureIndex({ fieldName: 'tokenHash', unique: true });
  await sessionsStore.ensureIndex({ fieldName: 'userId' });
  await uploadsStore.ensureIndex({ fieldName: 'jobId', unique: true });
  await uploadLogsStore.ensureIndex({ fieldName: 'jobId' });
  await uploadLogsStore.ensureIndex({ fieldName: 'sequence' });
  await apiLogsStore.ensureIndex({ fieldName: 'route' });

  initialized = true;
}

export function getLocalDatabaseDirectory() {
  return dbDirectory;
}
