import { execFile } from 'node:child_process';
import { platform } from 'node:os';
import { promisify } from 'node:util';
import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const execFileAsync = promisify(execFile);
const MAX_OUTPUT_CHARS = 16000;
const isProduction = process.env.NODE_ENV === 'production';

const commandsEnabled = process.env.OTA_RUNTIME_COMMANDS_ENABLED
  ? process.env.OTA_RUNTIME_COMMANDS_ENABLED === 'true'
  : !isProduction;

const blockedPatterns = [
  /(^|\s)rm\s+-rf(\s|$)/i,
  /(^|\s)del\s+\/f/i,
  /(^|\s)format\s+/i,
  /(^|\s)shutdown(\s|$)/i,
  /(^|\s)reboot(\s|$)/i,
  /(^|\s)poweroff(\s|$)/i,
  /(^|\s)mkfs/i,
  /(^|\s)diskpart(\s|$)/i,
];

const blockedCharactersPattern = /[;&|><`\r\n]/;
const blockedSubstitutionPattern = /\$\(/;

function getAllowedCommands() {
  const configured = process.env.OTA_RUNTIME_COMMAND_ALLOWLIST;
  const values = (configured || 'echo,dir,ls,pwd,whoami,node,python,py')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);

  return new Set(values);
}

function getCommandRoot(command: string) {
  return command.trim().split(/\s+/)[0]?.toLowerCase() || '';
}

function getBearerToken(request: Request) {
  const authorization = request.headers.get('authorization');
  if (!authorization) {
    return null;
  }

  const [scheme, token] = authorization.split(' ');
  if (!scheme || !token || scheme.toLowerCase() !== 'bearer') {
    return null;
  }

  return token.trim();
}

function normalizeOutput(value: string) {
  const cleaned = value.trim() || 'Command executed with no output.';
  return cleaned.length > MAX_OUTPUT_CHARS
    ? `${cleaned.slice(0, MAX_OUTPUT_CHARS)}\n...output truncated`
    : cleaned;
}

function isBlockedCommand(command: string) {
  return blockedPatterns.some((pattern) => pattern.test(command));
}

export async function POST(request: Request) {
  try {
    if (!commandsEnabled) {
      return NextResponse.json(
        {
          ok: false,
          output: 'Runtime command execution is disabled. Set OTA_RUNTIME_COMMANDS_ENABLED=true to enable it explicitly.',
        },
        { status: 403 }
      );
    }

    const payload = (await request.json()) as { command?: string };
    const command = (payload.command || '').trim();

    if (!command) {
      return NextResponse.json({ ok: false, output: 'Command is empty.' }, { status: 400 });
    }

    if (command.length > 300) {
      return NextResponse.json({ ok: false, output: 'Command is too long.' }, { status: 400 });
    }

    if (blockedCharactersPattern.test(command) || blockedSubstitutionPattern.test(command)) {
      return NextResponse.json(
        {
          ok: false,
          output: 'Command contains blocked shell control characters.',
        },
        { status: 400 }
      );
    }

    if (isBlockedCommand(command)) {
      return NextResponse.json(
        {
          ok: false,
          output: 'Blocked potentially destructive command. Use safer commands for runtime testing.',
        },
        { status: 400 }
      );
    }

    const allowedCommands = getAllowedCommands();
    if (allowedCommands.size === 0) {
      return NextResponse.json(
        {
          ok: false,
          output: 'No command allowlist configured. Set OTA_RUNTIME_COMMAND_ALLOWLIST to permitted command roots.',
        },
        { status: 503 }
      );
    }

    const commandRoot = getCommandRoot(command);
    if (!commandRoot || !allowedCommands.has(commandRoot)) {
      return NextResponse.json(
        {
          ok: false,
          output: `Command root '${commandRoot || 'unknown'}' is not allowlisted.`,
        },
        { status: 403 }
      );
    }

    const auth = await authenticateRequest(request);
    const providedToken = getBearerToken(request);
    const expectedToken = process.env.OTA_RUNTIME_COMMAND_TOKEN?.trim();
    const hasServiceTokenAccess = Boolean(expectedToken && providedToken === expectedToken);

    if (!auth && !hasServiceTokenAccess) {
      return NextResponse.json(
        {
          ok: false,
          output: 'Unauthorized runtime command request.',
        },
        { status: 401 }
      );
    }

    if (isProduction && !expectedToken && !auth) {
      return NextResponse.json(
        {
          ok: false,
          output: 'Production command execution requires a valid login session or OTA_RUNTIME_COMMAND_TOKEN.',
        },
        { status: 503 }
      );
    }

    const cwd = process.env.OTA_RUNTIME_COMMAND_CWD || process.cwd();
    const isWindows = platform() === 'win32';

    const shell = isWindows ? 'powershell.exe' : 'bash';
    const args = isWindows
      ? ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', command]
      : ['-lc', command];

    const { stdout, stderr } = await execFileAsync(shell, args, {
      cwd,
      timeout: 15000,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    });

    const output = normalizeOutput([stdout, stderr].filter(Boolean).join('\n'));

    return NextResponse.json({
      ok: true,
      output,
    });
  } catch (error: unknown) {
    const err = error as { stdout?: string; stderr?: string; message?: string };
    const output = normalizeOutput([err.stdout, err.stderr, err.message].filter(Boolean).join('\n') || 'Command execution failed.');

    return NextResponse.json(
      {
        ok: false,
        output,
      },
      { status: 500 }
    );
  }
}
