import crypto from 'node:crypto';
import {
  initializeLocalDatabase,
  sessionsStore,
  usersStore,
  type SessionRecord,
  type UserRecord,
} from '@/lib/local-database';

const SESSION_TTL_HOURS = Number(process.env.OTA_SESSION_TTL_HOURS || 24);

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

export async function ensureDefaultAdminUser() {
  await initializeLocalDatabase();

  const existingUsers = await usersStore.count({});
  if (existingUsers > 0) {
    return;
  }

  const username = (process.env.OTA_ADMIN_USERNAME || 'admin').trim();
  const password = (process.env.OTA_ADMIN_PASSWORD || 'admin123').trim();

  await usersStore.insert({
    username,
    passwordHash: hashPassword(password),
    role: 'admin',
    isActive: true,
  });
}

export async function loginWithPassword(username: string, password: string) {
  await ensureDefaultAdminUser();

  const normalizedUsername = username.trim();
  if (!normalizedUsername || !password.trim()) {
    return null;
  }

  const user = await usersStore.findOne({ username: normalizedUsername });
  if (!user || !user.isActive) {
    return null;
  }

  if (!verifyPassword(password, user.passwordHash)) {
    return null;
  }

  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);
  const expiresAt = Date.now() + SESSION_TTL_HOURS * 60 * 60 * 1000;

  await sessionsStore.insert({
    tokenHash,
    userId: String(user._id),
    expiresAt,
    revoked: false,
  });

  await usersStore.update(
    { _id: user._id },
    {
      $set: {
        lastLoginAt: new Date().toISOString(),
      },
    }
  );

  return {
    token: rawToken,
    expiresAt,
    user: sanitizeUser({
      ...user,
      lastLoginAt: new Date().toISOString(),
    }),
  };
}

export async function authenticateRequest(request: Request): Promise<AuthContext | null> {
  await ensureDefaultAdminUser();

  const token = parseBearerToken(request);
  if (!token) {
    return null;
  }

  const tokenHash = hashToken(token);
  const session = await sessionsStore.findOne({ tokenHash, revoked: false });
  if (!session) {
    return null;
  }

  if (session.expiresAt <= Date.now()) {
    await sessionsStore.update(
      { _id: session._id },
      {
        $set: {
          revoked: true,
        },
      }
    );
    return null;
  }

  const user = await usersStore.findOne({ _id: session.userId, isActive: true });
  if (!user) {
    return null;
  }

  return {
    user: sanitizeUser(user),
    session,
    tokenHash,
  };
}

export async function revokeRequestToken(request: Request) {
  const token = parseBearerToken(request);
  if (!token) {
    return;
  }

  const tokenHash = hashToken(token);
  await sessionsStore.update(
    { tokenHash },
    {
      $set: {
        revoked: true,
      },
    },
    { multi: true }
  );
}

export async function listRecentUsers(limit = 10) {
  await ensureDefaultAdminUser();
  return usersStore.find({}).sort({ updatedAt: -1 }).limit(limit).project({ passwordHash: 0 });
}
