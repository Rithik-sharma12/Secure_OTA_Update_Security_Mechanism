import crypto from 'node:crypto';
import {
  initializeLocalDatabase,
  sessionsStore,
  usersStore,
  type SessionRecord,
  type UserRecord,
} from '@/lib/local-database';

const SESSION_TTL_HOURS = Number(process.env.OTA_SESSION_TTL_HOURS || 24);
const DISALLOWED_BOOTSTRAP_USERNAMES = new Set(['admin', 'administrator', 'root']);
const DISALLOWED_BOOTSTRAP_PASSWORDS = new Set([
  'admin',
  'admin123',
  'password',
  'password123',
  'change-this-password',
  '123456',
  '12345678',
]);

// New constant for the session cookie name
export const SESSION_COOKIE_NAME = 'ota_session_token';

export interface PublicUser {
  id: string;
  username: string;
  role: UserRecord['role'];
  lastLoginAt?: string | Date;
}

export interface AuthContext {
  user: PublicUser;
  session: SessionRecord;
  tokenHash: string;
}

type CookieReadableRequest = Request & {
  cookies?: {
    get: (name: string) => { value: string } | undefined;
  };
};

function hashPassword(password: string, salt = crypto.randomBytes(16).toString('hex')) {
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password: string, storedHash: string) {
  const [salt, expected] = storedHash.split(':');
  if (!salt || !expected) {
    return false;
  }

  const actual = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

function hashToken(token: string) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function sanitizeUser(user: UserRecord): PublicUser {
  return {
    id: String(user._id || ''),
    username: user.username,
    role: user.role,
    lastLoginAt: user.lastLoginAt,
  };
}

function parseBearerToken(request: Request) {
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

function readCookieValue(request: Request, cookieName: string) {
  const cookieRequest = request as CookieReadableRequest;
  const cookieFromRequest = cookieRequest.cookies?.get(cookieName)?.value;
  if (cookieFromRequest) {
    return cookieFromRequest;
  }

  const cookieHeader = request.headers.get('cookie');
  if (!cookieHeader) {
    return null;
  }

  const tokenPair = cookieHeader
    .split(';')
    .map((entry) => entry.trim())
    .find((entry) => entry.startsWith(`${cookieName}=`));

  if (!tokenPair) {
    return null;
  }

  const [, value = ''] = tokenPair.split('=');
  return decodeURIComponent(value);
}

function readBootstrapCredentials() {
  const username = (process.env.OTA_ADMIN_USERNAME || '').trim();
  const password = (process.env.OTA_ADMIN_PASSWORD || '').trim();

  if (!username || !password) {
    throw new Error('Missing OTA admin bootstrap credentials. Set OTA_ADMIN_USERNAME and OTA_ADMIN_PASSWORD before startup.');
  }

  if (DISALLOWED_BOOTSTRAP_USERNAMES.has(username.toLowerCase())) {
    throw new Error('OTA_ADMIN_USERNAME uses a default/demo value. Set a unique production username.');
  }

  if (password.length < 12 || DISALLOWED_BOOTSTRAP_PASSWORDS.has(password.toLowerCase())) {
    throw new Error('OTA_ADMIN_PASSWORD must be at least 12 characters and not a default/demo value.');
  }

  return { username, password };
}

export async function ensureDefaultAdminUser() {
  await initializeLocalDatabase();

  const existingUsers = await usersStore.count({});
  if (existingUsers > 0) {
    return;
  }

  const { username, password } = readBootstrapCredentials();

  try {
    await usersStore.insert({
      username,
      passwordHash: hashPassword(password),
      role: 'admin',
      isActive: true,
    });
  } catch (dbError: unknown) {
    const message = dbError instanceof Error ? dbError.message : String(dbError);
    logger.error('Auth', `Failed to insert default admin user: ${message}`, dbError);
    errorTracker.track(dbError, 'Auth:DBInsert:DefaultAdmin');
    throw new OTAError(`Failed to create default admin user: ${message}`, 'DB_INSERT_FAILED', 500, { originalError: dbError });
  }
}

import { logger, errorTracker } from '@/lib/logger';
import { OTAError, UnauthorizedError } from '@/lib/error-handler';

export async function loginWithPassword(username: string, password: string) {
  await ensureDefaultAdminUser();

  const normalizedUsername = username.trim();
  if (!normalizedUsername || !password.trim()) {
    return null;
  }

  let user: UserRecord | null = null;
  try {
    user = await usersStore.findOne({ username: normalizedUsername });
  } catch (dbError: unknown) {
    logger.error('Auth', `Failed to find user ${normalizedUsername}: ${dbError instanceof Error ? dbError.message : String(dbError)}`, dbError);
    errorTracker.track(dbError, 'Auth:DBFind:User');
    return null; // Treat as not found for security
  }

  if (!user || !user.isActive) {
    return null;
  }

  if (!verifyPassword(password, user.passwordHash)) {
    logger.warn('Auth', `Failed login attempt for user: ${normalizedUsername}`);
    return null;
  }

  const sessionToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(sessionToken);
  const expiresAt = Date.now() + SESSION_TTL_HOURS * 60 * 60 * 1000;
  
  try {
    await sessionsStore.insert({
      tokenHash,
      userId: String(user._id),
      expiresAt,
      revoked: false,
    });
  } catch (dbError: unknown) {
    logger.error('Auth', `Failed to insert session for user ${user._id}: ${dbError instanceof Error ? dbError.message : String(dbError)}`, dbError);
    errorTracker.track(dbError, 'Auth:DBInsert:Session');
    throw new OTAError('Failed to create session', 'SESSION_CREATE_FAILED', 500, { userId: user._id, originalError: dbError });
  }

  try {
    await usersStore.update(
    { _id: user._id },
    {
      $set: {
        lastLoginAt: new Date().toISOString(),
      },
    }
  );
  } catch (dbError: unknown) {
    logger.error('Auth', `Failed to update lastLoginAt for user ${user._id}: ${dbError instanceof Error ? dbError.message : String(dbError)}`, dbError);
    errorTracker.track(dbError, 'Auth:DBUpdate:LastLogin');
    // Do not re-throw, as session is already created. Log and continue.
  }

  return {
    sessionToken,
    expiresAt,
    user: sanitizeUser({
      ...user,
      lastLoginAt: new Date().toISOString(),
    }),
  };
}

export async function authenticateRequest(request: Request): Promise<AuthContext | null> {
  await ensureDefaultAdminUser();

  // Prioritize token from HttpOnly cookie
  const cookieToken = readCookieValue(request, SESSION_COOKIE_NAME);
  let token = cookieToken;

  // Fallback to Authorization header if no cookie token (e.g., for testing or specific integrations)
  if (!token) {
    token = parseBearerToken(request);
  }
  if (!token) { // If no token found from either source
    return null;
  }

  const tokenHash = hashToken(token);
  let session: SessionRecord | null = null;
  try {
    session = await sessionsStore.findOne({ tokenHash, revoked: false });
  } catch (dbError: unknown) {
    logger.error('Auth', `Failed to find session by token hash: ${dbError instanceof Error ? dbError.message : String(dbError)}`, dbError);
    errorTracker.track(dbError, 'Auth:DBFind:SessionByToken');
    return null;
  }
  if (!session) {
    return null;
  }

  if (session.expiresAt <= Date.now()) {
    // Session expired, revoke it
    try {
      await sessionsStore.update(
        { _id: session._id },
        {
          $set: {
            revoked: true,
          },
        }
      );
      logger.info('Auth', `Expired session revoked for user ${session.userId}`);
    } catch (dbError: unknown) {
      logger.error('Auth', `Failed to revoke expired session ${session._id}: ${dbError instanceof Error ? dbError.message : String(dbError)}`, dbError);
      errorTracker.track(dbError, 'Auth:DBUpdate:RevokeExpiredSession');
    }

    return null;
  }

  let user: UserRecord | null = null;
  try {
    user = await usersStore.findOne({ _id: session.userId, isActive: true });
  } catch (dbError: unknown) {
    logger.error('Auth', `Failed to find user ${session.userId} for active session: ${dbError instanceof Error ? dbError.message : String(dbError)}`, dbError);
    errorTracker.track(dbError, 'Auth:DBFind:UserForSession');
  }
  if (!user) {
    return null;
  }

  return {
    user: sanitizeUser(user),
    session,
    tokenHash,
  };
}

export async function revokeRequestToken(request: Request) { // Modified to accept a Request object
  const token = readCookieValue(request, SESSION_COOKIE_NAME);

  if (!token) { // If no token in cookie, try Authorization header as fallback
    const bearerToken = parseBearerToken(request);
    if (!bearerToken) {
      return; // No token found in either source
    }
    // Use bearerToken for revocation if no cookie token was found
    // This might happen if the client-side token was stored in localStorage previously
    // or if a different auth mechanism is used.
    const tokenHash = hashToken(bearerToken);
    try {
      await sessionsStore.update(
        { tokenHash },
        {
          $set: {
            revoked: true,
          },
        },
        { multi: true }
      );
      logger.info('Auth', `Session revoked for bearer token hash: ${tokenHash}`);
    } catch (dbError: unknown) {
      logger.error('Auth', `Failed to revoke session for bearer token hash ${tokenHash}: ${dbError instanceof Error ? dbError.message : String(dbError)}`, dbError);
      errorTracker.track(dbError, 'Auth:DBUpdate:RevokeBearerSession');
    }
    return;
  }

  const tokenHash = hashToken(token);
  try {
    await sessionsStore.update(
      { tokenHash }, // Find session by hash
      { $set: { revoked: true } }, // Mark as revoked
      { multi: true } // Update all matching sessions (should be only one due to unique index)
    );
    logger.info('Auth', `Session revoked for cookie token hash: ${tokenHash}`);
  } catch (dbError: unknown) {
    logger.error('Auth', `Failed to revoke session for cookie token hash ${tokenHash}: ${dbError instanceof Error ? dbError.message : String(dbError)}`, dbError);
    errorTracker.track(dbError, 'Auth:DBUpdate:RevokeSession');
  }
}

export async function listRecentUsers(limit = 10) {
  await ensureDefaultAdminUser();
  try {
    return await usersStore.find({}).sort({ updatedAt: -1 }).limit(limit).project({ passwordHash: 0 });
  } catch (dbError: unknown) {
    logger.error('Auth', `Failed to list recent users: ${dbError instanceof Error ? dbError.message : String(dbError)}`, dbError);
    errorTracker.track(dbError, 'Auth:DBFind:ListRecentUsers');
    return []; // Return empty array on failure
  }
}