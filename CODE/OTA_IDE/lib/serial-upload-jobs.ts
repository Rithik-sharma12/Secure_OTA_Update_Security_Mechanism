import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { uploadsStore, uploadLogsStore, type UploadRecord } from '@/lib/local-database';
import { logger, errorTracker } from '@/lib/logger';

export type UploadJobStatus = 'queued' | 'compiling' | 'uploading' | 'success' | 'failed';

export type UploadLogEntry = {
  sequence: number;
  level: 'info' | 'warning' | 'error' | 'success';
  message: string;
  loggedAt: string;
};

export type UploadJobSnapshot = {
  jobId: string;
  status: UploadJobStatus;
  progress: number;
  startedAt: string;
  completedAt?: string;
  errorMessage?: string;
  logs: UploadLogEntry[];
  filePath: string;
  fileName: string;
  boardType: string;
  fqbn: string;
  comPort: string;
  baudRate: string;
};

export type StartUploadInput = {
  filePath: string;
  boardType: string;
  comPort: string;
  baudRate: string;
  userId: string;
};

const arduinoCliPath = process.env.ARDUINO_CLI_PATH || 'arduino-cli';
const maxLogsPerJob = Number(process.env.OTA_UPLOAD_MAX_LOGS || 1000);
const jobs = new Map<string, UploadJobSnapshot>();

const boardFqbnMap: Record<string, string> = {
  ESP32: process.env.OTA_FQBN_ESP32 || 'esp32:esp32:esp32',
  ESP8266: process.env.OTA_FQBN_ESP8266 || 'esp8266:esp8266:generic',
  ATmega328P: process.env.OTA_FQBN_ATMEGA328P || 'arduino:avr:uno',
  STM32F103: process.env.OTA_FQBN_STM32F103 || 'STMicroelectronics:stm32:GenF1',
};

function nowIso() {
  return new Date().toISOString();
}

function isWindowsComPort(comPort: string) {
  return /^COM\d+$/i.test(comPort.trim());
}

function resolveSketchPath(inputPath: string) {
  const absolutePath = path.resolve(inputPath);
  const extension = path.extname(absolutePath).toLowerCase();

  if (extension !== '.ino') {
    throw new Error('Only .ino sketch uploads are currently supported for ESP32 serial upload.');
  }

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Sketch file not found: ${absolutePath}`);
  }

  return {
    filePath: absolutePath,
    fileName: path.basename(absolutePath),
    sketchDirectory: path.dirname(absolutePath),
  };
}

function resolveFqbn(boardType: string) {
  const fqbn = boardFqbnMap[boardType];
  if (!fqbn) {
    throw new Error(`Unsupported board type '${boardType}'. Add OTA_FQBN_${boardType.toUpperCase()} env var to map it.`);
  }

  return fqbn;
}

async function hashFile(filePath: string) {
  const hash = crypto.createHash('sha256');
  const stream = fs.createReadStream(filePath);

  await new Promise<void>((resolve, reject) => {
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve());
  });

  return hash.digest('hex');
}

function getJob(jobId: string) {
  return jobs.get(jobId) || null;
}

function updateJob(jobId: string, patch: Partial<UploadJobSnapshot>) {
  const current = jobs.get(jobId);
  if (!current) {
    return;
  }

  jobs.set(jobId, {
    ...current,
    ...patch,
  });
}

async function appendUploadLog(jobId: string, level: UploadLogEntry['level'], message: string) {
  const current = jobs.get(jobId);
  if (!current) {
    return;
  }

  const sequence = (current.logs[current.logs.length - 1]?.sequence || 0) + 1;
  const logEntry: UploadLogEntry = {
    sequence,
    level,
    message,
    loggedAt: nowIso(),
  };

  const nextLogs = [...current.logs, logEntry];
  current.logs = nextLogs.slice(-maxLogsPerJob);
  jobs.set(jobId, current);

  await uploadLogsStore.insert({
    jobId,
    sequence,
    level,
    message,
    loggedAt: logEntry.loggedAt,
  });
}

async function updateUploadRecord(jobId: string, patch: Partial<UploadRecord>) {
  await uploadsStore.update(
    { jobId },
    {
      $set: patch,
    },
    { upsert: false }
  );
}

function updateProgress(jobId: string, progress: number) {
  const current = jobs.get(jobId);
  if (!current) {
    return;
  }

  const normalized = Math.max(0, Math.min(100, progress));
  if (normalized <= current.progress) {
    return;
  }

  updateJob(jobId, { progress: normalized });
}

function parseProgressFromLine(jobId: string, stage: 'compile' | 'upload', line: string) {
  if (stage === 'compile') {
    if (/Compiling sketch/i.test(line)) {
      updateProgress(jobId, 10);
    }

    if (/Compiling core/i.test(line)) {
      updateProgress(jobId, 30);
    }

    if (/Sketch uses/i.test(line)) {
      updateProgress(jobId, 55);
    }

    return;
  }

  const percentageMatch = line.match(/(\d{1,3})%/);
  if (percentageMatch) {
    const uploadPercentage = Math.min(100, Number(percentageMatch[1]));
    updateProgress(jobId, 55 + Math.round(uploadPercentage * 0.44));
  }

  if (/Hash of data verified|Hard resetting|Leaving\.\.\./i.test(line)) {
    updateProgress(jobId, 99);
  }
}

async function runProcess(
  jobId: string,
  stage: 'compile' | 'upload',
  command: string,
  args: string[],
  cwd: string,
) {
  await appendUploadLog(jobId, 'info', `Running: ${command} ${args.join(' ')}`);

  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    }) as ChildProcessWithoutNullStreams;

    let stdErrBuffer = '';

    const consumeChunk = (chunk: Buffer | string, level: UploadLogEntry['level']) => {
      const lines = String(chunk)
        .replace(/\r\n/g, '\n')
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);

      lines.forEach((line) => {
        if (level === 'error') {
          stdErrBuffer = line;
        }

        void appendUploadLog(jobId, level, line);
        parseProgressFromLine(jobId, stage, line);
      });
    };

    child.stdout.on('data', (chunk) => consumeChunk(chunk, 'info'));
    child.stderr.on('data', (chunk) => consumeChunk(chunk, 'error'));

    child.on('error', (error) => {
      logger.error('SerialUploadJobs', `Process spawn error for command "${command}"`, error, { jobId, stage });
      errorTracker.track(error, `SerialUploadJobs:ProcessSpawn:${stage}`);
      reject(error);
    });

    child.on('close', (code) => {
      if (code !== 0) {
        logger.error('SerialUploadJobs', `Process exited with non-zero code ${code} for command "${command}"`, new Error(stdErrBuffer || `${stage} command failed with exit code ${code}`), { jobId, stage, exitCode: code });
        errorTracker.track(new Error(stdErrBuffer || `${stage} command failed with exit code ${code}`), `SerialUploadJobs:ProcessExit:${stage}`);
      }
      if (code === 0) {
        resolve();
        return;
      }

      reject(new Error(stdErrBuffer || `${stage} command failed with exit code ${code}`));
    });
  });
}

async function runUploadJob(jobId: string, sketchDirectory: string) {
  const current = jobs.get(jobId);
  if (!current) {
    return;
  }

  try {
    updateJob(jobId, { status: 'compiling', progress: 5 });
    await updateUploadRecord(jobId, { status: 'compiling', progress: 5 });
    await appendUploadLog(jobId, 'info', 'Compilation started.');

    await runProcess(
      jobId,
      'compile',
      arduinoCliPath,
      ['compile', '--fqbn', current.fqbn, '--warnings', 'all', sketchDirectory],
      sketchDirectory
    );

    updateJob(jobId, { status: 'uploading', progress: Math.max(current.progress, 60) });
    await updateUploadRecord(jobId, {
      status: 'uploading',
      progress: Math.max(current.progress, 60),
    });
    await appendUploadLog(jobId, 'info', 'Compilation complete. Serial upload started.');

    await runProcess(
      jobId,
      'upload',
      arduinoCliPath,
      ['upload', '--fqbn', current.fqbn, '--port', current.comPort, '--verbose', sketchDirectory],
      sketchDirectory
    );

    updateJob(jobId, {
      status: 'success',
      progress: 100,
      completedAt: nowIso(),
    });

    await updateUploadRecord(jobId, {
      status: 'success',
      progress: 100,
      endedAt: nowIso(),
      errorMessage: undefined,
    });

    await appendUploadLog(jobId, 'success', 'Upload completed successfully.');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Upload failed unexpectedly.';

    logger.error('SerialUploadJobs', `Upload job ${jobId} failed`, error);
    errorTracker.track(error, `SerialUploadJobs:UploadJob:${jobId}`);
    updateJob(jobId, {
      status: 'failed',
      errorMessage: message,
      completedAt: nowIso(),
    });

    await updateUploadRecord(jobId, {
      status: 'failed',
      endedAt: nowIso(),
      errorMessage: message,
    });

    await appendUploadLog(jobId, 'error', message);
  }
}

export async function startSerialUpload(input: StartUploadInput) {
  const sketch = resolveSketchPath(input.filePath);

  if (!isWindowsComPort(input.comPort)) {
    throw new Error('Invalid COM port format. Use values like COM3.');
  }

  const fqbn = resolveFqbn(input.boardType);
  const fileHash = await hashFile(sketch.filePath);
  const jobId = crypto.randomUUID();

  const snapshot: UploadJobSnapshot = {
    jobId,
    status: 'queued',
    progress: 0,
    startedAt: nowIso(),
    logs: [],
    filePath: sketch.filePath,
    fileName: sketch.fileName,
    boardType: input.boardType,
    fqbn,
    comPort: input.comPort,
    baudRate: input.baudRate,
  };

  jobs.set(jobId, snapshot);

  try {
    await uploadsStore.insert({
      jobId,
      userId: input.userId,
      filePath: sketch.filePath,
      fileName: sketch.fileName,
      fileHash,
      boardType: input.boardType,
      fqbn,
      comPort: input.comPort,
      baudRate: input.baudRate,
      status: 'queued',
      progress: 0,
      startedAt: snapshot.startedAt,
    });
  } catch (dbError: unknown) {
    const errorMessage = dbError instanceof Error ? dbError.message : String(dbError);
    logger.error('SerialUploadJobs', `Failed to insert initial upload record for job ${jobId}: ${errorMessage}`, dbError);
    errorTracker.track(dbError, `SerialUploadJobs:DBInsert:Initial`);
  }

  await appendUploadLog(jobId, 'info', 'Upload job created and queued.');

  void runUploadJob(jobId, sketch.sketchDirectory);

  return snapshot;
}

export async function getUploadJobSnapshot(jobId: string, sinceSequence = 0) {
  const activeJob = getJob(jobId);
  if (activeJob) {
    return {
      ...activeJob,
      logs: activeJob.logs.filter((entry) => entry.sequence > sinceSequence),
      lastSequence: activeJob.logs[activeJob.logs.length - 1]?.sequence || 0, // This will be handled by nedb-promises
    };
  }

  let persistedJob: UploadRecord | null = null;
  try {
    persistedJob = await uploadsStore.findOne({ jobId });
  } catch (dbError: unknown) {
    const errorMessage = dbError instanceof Error ? dbError.message : String(dbError);
    logger.error('SerialUploadJobs', `Failed to find persisted job ${jobId}: ${errorMessage}`, dbError);
    errorTracker.track(dbError, `SerialUploadJobs:DBFind:Job`);
    return null; // Cannot proceed without job record
  }

  if (!persistedJob) {
    return null;
  }

  let logs: UploadLogRecord[] = [];
  try {
    logs = await uploadLogsStore.find({ jobId, sequence: { $gt: sinceSequence } }).sort({ sequence: 1 });
  } catch (dbError: unknown) {
    logger.error('SerialUploadJobs', `Failed to find logs for job ${jobId}: ${dbError instanceof Error ? dbError.message : String(dbError)}`, dbError);
    errorTracker.track(dbError, `SerialUploadJobs:DBFind:Logs`);
  }

  let lastLog: UploadLogRecord | null = null;
  try {
    lastLog = await uploadLogsStore.findOne({ jobId }).sort({ sequence: -1 });
  } catch (dbError: unknown) {
    logger.error('SerialUploadJobs', `Failed to find last log for job ${jobId}: ${dbError instanceof Error ? dbError.message : String(dbError)}`, dbError);
    errorTracker.track(dbError, `SerialUploadJobs:DBFind:LastLog`);
  }

  return {
    jobId,
    status: persistedJob.status,
    progress: persistedJob.progress,
    startedAt: persistedJob.startedAt,
    completedAt: persistedJob.endedAt,
    errorMessage: persistedJob.errorMessage,
    filePath: persistedJob.filePath,
    fileName: persistedJob.fileName,
    boardType: persistedJob.boardType,
    fqbn: persistedJob.fqbn,
    comPort: persistedJob.comPort,
    baudRate: persistedJob.baudRate,
    logs: logs.map((entry) => ({
      sequence: entry.sequence,
      level: entry.level,
      message: entry.message,
      loggedAt: entry.loggedAt,
    })),
    lastSequence: lastLog?.sequence || 0,
  };
}
