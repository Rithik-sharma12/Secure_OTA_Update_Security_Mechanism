import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { uploadsStore, uploadLogsStore, type UploadRecord, type UploadLogRecord } from '@/lib/local-database';
import { logger, errorTracker } from '@/lib/logger';
import { detectConnectedSerialPorts, isConnectedComPort, normalizeComPortName } from '@/lib/serial-port-detection';

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
  /**
   * WiFi credentials baked into ota_config.h at compile time, so a freshly
   * flashed device can reach the gateway without the header being hand-edited.
   * Only meaningful for the WiFi-capable boards (ESP32/ESP8266).
   */
  wifiSsid?: string;
  wifiPassword?: string;
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

/**
 * Escape a value for embedding in a C string literal.
 *
 * Backslash must be escaped before the quote, or the quote's own escape would
 * be double-escaped. Line breaks are rejected outright: they are invalid in an
 * SSID or WPA passphrase anyway, and they are the one input that would break
 * out of the literal and produce a confusing compiler error rather than a
 * clear rejection here.
 */
function escapeCStringLiteral(value: string) {
  if (/[\r\n]/.test(value)) {
    throw new Error('WiFi credentials cannot contain line breaks.');
  }

  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Rewrite the value of a single `#define NAME "..."` line, leaving the macro
 * name and its surrounding whitespace alone.
 *
 * Only the two WiFi macros are ever touched. Everything else in the header —
 * BACKEND_URL, API keys, the encryption key, the pinned root CA, NTP servers —
 * is fleet-wide configuration, not per-device, and must survive untouched.
 */
function replaceDefine(source: string, macro: string, value: string) {
  // Matches the existing quoted value including any escaped characters inside.
  const pattern = new RegExp(`^([ \\t]*#define[ \\t]+${macro}[ \\t]+)"(?:[^"\\\\]|\\\\.)*"`, 'm');

  if (!pattern.test(source)) {
    throw new Error(
      `Could not find '#define ${macro}' in ota_config.h, so WiFi credentials cannot be injected.`
    );
  }

  const escaped = escapeCStringLiteral(value);

  // Function replacement, not a '$1' string: a password containing $& or $'
  // would otherwise be interpreted as a replacement pattern and mangled.
  return source.replace(pattern, (_match, prefix: string) => `${prefix}"${escaped}"`);
}

/**
 * Copy the sketch to a throwaway directory and patch the copy's ota_config.h.
 *
 * The sketch lives in a tracked git path whose ota_config.h is a committed
 * placeholder, so patching it in place would risk a real WiFi password landing
 * in a commit, and two concurrent flashes would overwrite each other's config.
 *
 * arduino-cli requires the sketch folder name to match the primary .ino file
 * name, so the copy keeps its original basename inside a temporary parent
 * rather than becoming the mkdtemp directory itself.
 */
function prepareFlashWorkspace(sketchDirectory: string, wifiSsid?: string, wifiPassword?: string) {
  const cleanupRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ota-flash-'));

  try {
    const workspace = path.join(cleanupRoot, path.basename(sketchDirectory));
    fs.cpSync(sketchDirectory, workspace, { recursive: true });

    if (wifiSsid) {
      const configPath = path.join(workspace, 'ota_config.h');
      if (!fs.existsSync(configPath)) {
        throw new Error(
          'ota_config.h was not found beside the sketch, so WiFi credentials cannot be injected.'
        );
      }

      let source = fs.readFileSync(configPath, 'utf8');
      source = replaceDefine(source, 'WIFI_SSID', wifiSsid);
      source = replaceDefine(source, 'WIFI_PASSWORD', wifiPassword ?? '');
      fs.writeFileSync(configPath, source, 'utf8');
    }

    return { workspace, cleanupRoot };
  } catch (error) {
    // Never leak the temp directory when preparation fails partway.
    fs.rmSync(cleanupRoot, { recursive: true, force: true });
    throw error;
  }
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
    });

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

async function runUploadJob(jobId: string, sketchDirectory: string, cleanupRoot?: string) {
  const current = jobs.get(jobId);
  if (!current) {
    // Nothing will run, so the workspace would otherwise be orphaned.
    if (cleanupRoot) {
      fs.rmSync(cleanupRoot, { recursive: true, force: true });
    }
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
  } finally {
    // The workspace holds a copy of ota_config.h carrying the WiFi password in
    // clear text, so it is removed whether the flash succeeded or failed.
    if (cleanupRoot) {
      try {
        fs.rmSync(cleanupRoot, { recursive: true, force: true });
      } catch (cleanupError) {
        logger.error(
          'SerialUploadJobs',
          `Failed to remove temporary flash workspace for job ${jobId}`,
          cleanupError
        );
      }
    }
  }
}

export async function startSerialUpload(input: StartUploadInput) {
  const sketch = resolveSketchPath(input.filePath);

  if (!isWindowsComPort(input.comPort)) {
    throw new Error('Invalid COM port format. Use values like COM3.');
  }

  const requestedPort = normalizeComPortName(input.comPort);
  const detection = detectConnectedSerialPorts();
  if (detection.supported) {
    if (detection.error) {
      throw new Error(`Unable to validate connected COM ports: ${detection.error}`);
    }

    if (!isConnectedComPort(requestedPort, detection.ports)) {
      const availablePorts = detection.ports.map((port) => port.path).join(', ');
      throw new Error(
        availablePorts
          ? `Requested port ${requestedPort} is not connected. Select one of: ${availablePorts}.`
          : `Requested port ${requestedPort} is not connected. No USB serial COM ports are currently detected.`
      );
    }
  }

  const fqbn = resolveFqbn(input.boardType);

  // Prepared before the job record exists so a bad credential (line breaks, a
  // header missing the WIFI_SSID define) fails the request outright instead of
  // leaving a queued job that can never run.
  const { workspace, cleanupRoot } = prepareFlashWorkspace(
    sketch.sketchDirectory,
    input.wifiSsid,
    input.wifiPassword
  );

  try {
    return await launchUploadJob(input, sketch, fqbn, requestedPort, workspace, cleanupRoot);
  } catch (error) {
    fs.rmSync(cleanupRoot, { recursive: true, force: true });
    throw error;
  }
}

async function launchUploadJob(
  input: StartUploadInput,
  sketch: ReturnType<typeof resolveSketchPath>,
  fqbn: string,
  requestedPort: string,
  workspace: string,
  cleanupRoot: string
) {
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
    comPort: requestedPort,
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
      comPort: requestedPort,
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

  if (input.wifiSsid) {
    // SSID only — the password is never written to the log or the job store.
    await appendUploadLog(jobId, 'info', `Configuring WiFi for SSID "${input.wifiSsid}".`);
  }

  void runUploadJob(jobId, workspace, cleanupRoot);

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
