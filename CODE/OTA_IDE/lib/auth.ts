import crypto from 'node:crypto';
import {
  initializeLocalDatabase,
  sessionsStore,
  usersStore,
  type SessionRecord,
  type UserRecord,
} from '@/lib/local-database';
import { logger, errorTracker } from '@/lib/logger';
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  OTAError,
  UnauthorizedError,
  ValidationError,
} from '@/lib/error-handler';

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
  const username = (process.env.OTA_ADMIN_USERNAME || 'sentinel_admin').trim();
  const password = (process.env.OTA_ADMIN_PASSWORD || 'SentinelSecure_2026!#').trim();

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
// ── User administration ────────────────────────────────────────────
//
// `role` was declared on UserRecord from the start but never compared
// against anything, so every signed-in account had identical power. These
// helpers are the write side of that model: they enforce the role, and they
// enforce the two invariants that keep an operator from locking everybody
// out — you cannot demote, deactivate or delete yourself, and the last
// active admin cannot be demoted, deactivated or deleted by anyone.
//
// Every mutation that changes what an account *is* (its password, its role,
// whether it is active) revokes that account's live sessions, so a demoted
// or disabled user cannot keep acting on a token issued before the change.

export type UserRole = UserRecord['role'];

export const USER_ROLES: readonly UserRole[] = ['admin', 'operator', 'viewer'] as const;

/** A user as the API returns it — never carries `passwordHash`. */
export interface ManagedUser extends PublicUser {
  isActive: boolean;
  createdAt?: string | Date;
  updatedAt?: string | Date;
}

const MIN_PASSWORD_LENGTH = 12;
const USERNAME_PATTERN = /^[A-Za-z0-9._-]{3,32}$/;

function sanitizeManagedUser(user: UserRecord): ManagedUser {
  return {
    ...sanitizeUser(user),
    isActive: Boolean(user.isActive),
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

/**
 * Same bar the bootstrap admin has to clear, applied to every password the
 * dashboard sets afterwards — otherwise `OTA_ADMIN_PASSWORD`'s 12-character
 * minimum is just theatre that a later "change password" walks straight past.
 */
export function assertPasswordPolicy(password: unknown): string {
  const candidate = typeof password === 'string' ? password : '';

  if (candidate.length < MIN_PASSWORD_LENGTH) {
    throw new ValidationError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  }

  if (DISALLOWED_BOOTSTRAP_PASSWORDS.has(candidate.toLowerCase())) {
    throw new ValidationError('That password is too common. Choose something unique.');
  }

  return candidate;
}

function normalizeUsername(raw: unknown): string {
  const candidate = String(raw ?? '').trim();

  if (!USERNAME_PATTERN.test(candidate)) {
    throw new ValidationError('Username must be 3-32 characters, using letters, digits, dot, dash or underscore.');
  }

  if (DISALLOWED_BOOTSTRAP_USERNAMES.has(candidate.toLowerCase())) {
    throw new ValidationError(`"${candidate}" is a reserved username. Pick something specific to the person.`);
  }

  return candidate;
}

function normalizeRole(raw: unknown): UserRole {
  const candidate = String(raw ?? '').trim() as UserRole;

  if (!USER_ROLES.includes(candidate)) {
    throw new ValidationError(`Role must be one of: ${USER_ROLES.join(', ')}.`);
  }

  return candidate;
}

/** Active admins other than `excludeUserId`. Zero means the excluded one is the last. */
async function countOtherActiveAdmins(excludeUserId: string): Promise<number> {
  const admins = await usersStore.find({ role: 'admin', isActive: true });
  return admins.filter((admin) => String(admin._id) !== String(excludeUserId)).length;
}

/**
 * Revoke a user's sessions. `exceptTokenHash` keeps the caller's own session
 * alive, which is what you want when someone changes their own password:
 * every other device is signed out, the browser in front of you is not.
 */
export async function revokeSessionsForUser(userId: string, exceptTokenHash?: string) {
  await initializeLocalDatabase();

  try {
    const sessions = await sessionsStore.find({ userId: String(userId), revoked: false });
    const doomed = sessions.filter((session) => session.tokenHash !== exceptTokenHash);

    await Promise.all(
      doomed.map((session) => sessionsStore.update({ _id: session._id }, { $set: { revoked: true } }))
    );
  } catch (dbError: unknown) {
    logger.error('Auth', `Failed to revoke sessions for user ${userId}`, dbError);
    errorTracker.track(dbError, 'Auth:DBUpdate:RevokeUserSessions');
    throw new OTAError('Failed to revoke existing sessions.', 'SESSION_REVOKE_FAILED', 500, { userId });
  }
}

async function findUserOrThrow(userId: string): Promise<UserRecord> {
  await initializeLocalDatabase();

  const user = await usersStore.findOne({ _id: String(userId) });
  if (!user) {
    throw new NotFoundError('User not found.');
  }

  return user;
}

/** The signed-in user's own record, for the profile page. */
export async function getManagedUser(userId: string): Promise<ManagedUser> {
  return sanitizeManagedUser(await findUserOrThrow(userId));
}

export async function listUsers(): Promise<ManagedUser[]> {
  await ensureDefaultAdminUser();

  const users = await usersStore.find({});
  return users
    .map(sanitizeManagedUser)
    .sort((left, right) => left.username.localeCompare(right.username));
}

export async function createUser(input: {
  username: unknown;
  password: unknown;
  role: unknown;
  isActive?: unknown;
}): Promise<ManagedUser> {
  await initializeLocalDatabase();

  const username = normalizeUsername(input.username);
  const role = normalizeRole(input.role);
  const password = assertPasswordPolicy(input.password);

  if (await usersStore.findOne({ username })) {
    throw new ConflictError(`A user named "${username}" already exists.`);
  }

  try {
    const created = await usersStore.insert({
      username,
      passwordHash: hashPassword(password),
      role,
      isActive: input.isActive === undefined ? true : Boolean(input.isActive),
    });

    logger.info('Auth', `Created user ${username} with role ${role}`);
    return sanitizeManagedUser(created);
  } catch (dbError: unknown) {
    // The unique index on `username` is the real race-safe check; the lookup
    // above only produces a friendlier message in the common case.
    const message = dbError instanceof Error ? dbError.message : String(dbError);
    if (/unique/i.test(message)) {
      throw new ConflictError(`A user named "${username}" already exists.`);
    }

    logger.error('Auth', `Failed to create user ${username}: ${message}`, dbError);
    errorTracker.track(dbError, 'Auth:DBInsert:CreateUser');
    throw new OTAError('Failed to create the user.', 'DB_INSERT_FAILED', 500);
  }
}

export async function updateUser(
  userId: string,
  patch: { username?: unknown; role?: unknown; isActive?: unknown; password?: unknown },
  actingUserId: string
): Promise<ManagedUser> {
  const user = await findUserOrThrow(userId);
  const isSelf = String(user._id) === String(actingUserId);
  const changes: Partial<UserRecord> = {};

  if (patch.username !== undefined) {
    const username = normalizeUsername(patch.username);
    if (username !== user.username) {
      if (await usersStore.findOne({ username })) {
        throw new ConflictError(`A user named "${username}" already exists.`);
      }
      changes.username = username;
    }
  }

  if (patch.role !== undefined) {
    const role = normalizeRole(patch.role);
    if (role !== user.role) {
      if (isSelf) {
        throw new ForbiddenError('You cannot change your own role. Ask another admin.');
      }
      if (user.role === 'admin' && (await countOtherActiveAdmins(String(user._id))) === 0) {
        throw new ForbiddenError('This is the last active admin. Promote another admin first.');
      }
      changes.role = role;
    }
  }

  if (patch.isActive !== undefined) {
    const isActive = Boolean(patch.isActive);
    if (isActive !== user.isActive) {
      if (!isActive) {
        if (isSelf) {
          throw new ForbiddenError('You cannot deactivate your own account.');
        }
        if (user.role === 'admin' && (await countOtherActiveAdmins(String(user._id))) === 0) {
          throw new ForbiddenError('This is the last active admin. Promote another admin first.');
        }
      }
      changes.isActive = isActive;
    }
  }

  if (patch.password !== undefined) {
    changes.passwordHash = hashPassword(assertPasswordPolicy(patch.password));
  }

  if (Object.keys(changes).length === 0) {
    return sanitizeManagedUser(user);
  }

  try {
    await usersStore.update({ _id: user._id }, { $set: changes });
  } catch (dbError: unknown) {
    const message = dbError instanceof Error ? dbError.message : String(dbError);
    if (/unique/i.test(message)) {
      throw new ConflictError('That username is already taken.');
    }

    logger.error('Auth', `Failed to update user ${user._id}: ${message}`, dbError);
    errorTracker.track(dbError, 'Auth:DBUpdate:UpdateUser');
    throw new OTAError('Failed to update the user.', 'DB_UPDATE_FAILED', 500);
  }

  // A new password, a new role, or a deactivation all mean the tokens issued
  // under the old state must stop working.
  if (changes.passwordHash || changes.role || changes.isActive === false) {
    await revokeSessionsForUser(String(user._id));
  }

  logger.info('Auth', `Updated user ${user.username}: ${Object.keys(changes).join(', ')}`);
  return sanitizeManagedUser(await findUserOrThrow(String(user._id)));
}

export async function deleteUser(userId: string, actingUserId: string): Promise<ManagedUser> {
  const user = await findUserOrThrow(userId);

  if (String(user._id) === String(actingUserId)) {
    throw new ForbiddenError('You cannot delete your own account.');
  }

  if (user.role === 'admin' && (await countOtherActiveAdmins(String(user._id))) === 0) {
    throw new ForbiddenError('This is the last active admin. Promote another admin first.');
  }

  try {
    await sessionsStore.remove({ userId: String(user._id) }, { multi: true });
    await usersStore.remove({ _id: user._id }, {});
  } catch (dbError: unknown) {
    logger.error('Auth', `Failed to delete user ${user._id}`, dbError);
    errorTracker.track(dbError, 'Auth:DBRemove:DeleteUser');
    throw new OTAError('Failed to delete the user.', 'DB_DELETE_FAILED', 500);
  }

  logger.info('Auth', `Deleted user ${user.username}`);
  return sanitizeManagedUser(user);
}

/**
 * Self-service credential change. Requires the current password even though
 * the session is already authenticated, so a borrowed open tab cannot be
 * turned into a permanent takeover.
 */
export async function updateOwnCredentials(
  auth: AuthContext,
  input: { username?: unknown; currentPassword?: unknown; newPassword?: unknown }
): Promise<ManagedUser> {
  const user = await findUserOrThrow(auth.user.id);
  const wantsPasswordChange = input.newPassword !== undefined && input.newPassword !== '';
  const wantsUsernameChange =
    input.username !== undefined && String(input.username).trim() !== user.username;

  if (!wantsPasswordChange && !wantsUsernameChange) {
    return sanitizeManagedUser(user);
  }

  const currentPassword = typeof input.currentPassword === 'string' ? input.currentPassword : '';
  if (!currentPassword || !verifyPassword(currentPassword, user.passwordHash)) {
    throw new UnauthorizedError('Current password is incorrect.');
  }

  const changes: Partial<UserRecord> = {};

  if (wantsUsernameChange) {
    const username = normalizeUsername(input.username);
    if (await usersStore.findOne({ username })) {
      throw new ConflictError(`A user named "${username}" already exists.`);
    }
    changes.username = username;
  }

  if (wantsPasswordChange) {
    changes.passwordHash = hashPassword(assertPasswordPolicy(input.newPassword));
  }

  try {
    await usersStore.update({ _id: user._id }, { $set: changes });
  } catch (dbError: unknown) {
    const message = dbError instanceof Error ? dbError.message : String(dbError);
    if (/unique/i.test(message)) {
      throw new ConflictError('That username is already taken.');
    }

    logger.error('Auth', `Failed to update own credentials for ${user._id}: ${message}`, dbError);
    errorTracker.track(dbError, 'Auth:DBUpdate:OwnCredentials');
    throw new OTAError('Failed to update your account.', 'DB_UPDATE_FAILED', 500);
  }

  // Sign out every other device, but keep the session making the request.
  if (changes.passwordHash) {
    await revokeSessionsForUser(String(user._id), auth.tokenHash);
  }

  return sanitizeManagedUser(await findUserOrThrow(String(user._id)));
}
