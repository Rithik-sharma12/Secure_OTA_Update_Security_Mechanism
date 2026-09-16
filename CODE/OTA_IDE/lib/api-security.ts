import { NextResponse } from 'next/server';
import { authenticateRequest, ensureDefaultAdminUser, type AuthContext, type UserRole } from '@/lib/auth';
import { apiLogsStore, initializeLocalDatabase } from '@/lib/local-database';
import { OTAError } from '@/lib/error-handler';
import { logger, errorTracker } from '@/lib/logger';

export type SecureApiContext = {
  auth: AuthContext | null;
};

type SecureHandler = (context: SecureApiContext) => Promise<NextResponse>;

type SecureApiOptions = {
  requireAuth?: boolean;
  /**
   * Roles allowed through. Naming any role implies requireAuth, and anyone
   * signed in with a different role gets 403 before the handler runs — the
   * one place role is actually compared, so route handlers never have to
   * remember to check it themselves.
   */
  requireRole?: readonly UserRole[];
};

export async function withSecureApi(
  request: Request,
  routeName: string,
  handler: SecureHandler,
  options: SecureApiOptions = {}
) {
  const startedAt = Date.now();
  let statusCode = 500;
  let userId: string | undefined;
  let errorMessage: string | undefined;

  try {
    await initializeLocalDatabase();
    await ensureDefaultAdminUser();

    const allowedRoles = options.requireRole ?? [];
    let auth: AuthContext | null = null;
    if (options.requireAuth || allowedRoles.length > 0) {
      auth = await authenticateRequest(request);
      if (!auth) {
        statusCode = 401;
        return NextResponse.json(
          {
            ok: false,
            error: 'Unauthorized request. Please login again.',
          },
          { status: 401 }
        );
      }

      userId = auth.user.id;

      if (allowedRoles.length > 0 && !allowedRoles.includes(auth.user.role)) {
        statusCode = 403;
        logger.warn(
          'ApiSecurity',
          `Role ${auth.user.role} denied on ${routeName} (requires ${allowedRoles.join(', ')})`,
          { userId }
        );
        return NextResponse.json(
          {
            ok: false,
            error: 'Your account does not have permission to perform this action.',
          },
          { status: 403 }
        );
      }
    }

    const response = await handler({ auth });
    statusCode = response.status;
    return response;
  } catch (error) {
    errorMessage = error instanceof Error ? error.message : 'Unknown API error';
    // An OTAError carries the status the handler meant (400 validation, 403
    // forbidden, 409 conflict...). Flattening those to 500 would tell the UI
    // "server broke" when the real answer is "that username is taken".
    statusCode = error instanceof OTAError ? error.statusCode : 500;

    if (statusCode >= 500) {
      logger.error('ApiSecurity', `Unhandled error in secure API route ${routeName}`, error);
      errorTracker.track(error, `ApiSecurity:Unhandled:${routeName}`);
    } else {
      logger.warn('ApiSecurity', `${routeName} rejected: ${errorMessage}`, { statusCode });
    }

    return NextResponse.json(
      {
        ok: false,
        error: errorMessage,
      },
      { status: statusCode }
    );
  } finally {
    const durationMs = Date.now() - startedAt;

    try {
      const route = routeName || new URL(request.url).pathname;
      await apiLogsStore.insert({
        route,
        method: request.method,
        statusCode,
        durationMs,
        userId,
        errorMessage,
      });
    } catch (logError: unknown) {
      logger.error('ApiSecurity', 'Failed to log API request', logError, { routeName, method: request.method, statusCode, durationMs, userId, errorMessage });
      errorTracker.track(logError, 'ApiSecurity:LogApiRequest');
      // Logging failures should never break API responses.
    }
  }
}
