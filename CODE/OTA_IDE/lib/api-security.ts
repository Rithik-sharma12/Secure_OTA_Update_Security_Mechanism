import { NextResponse } from 'next/server';
import { authenticateRequest, ensureDefaultAdminUser, type AuthContext } from '@/lib/auth';
import { apiLogsStore, initializeLocalDatabase } from '@/lib/local-database';

export type SecureApiContext = {
  auth: AuthContext | null;
};

type SecureHandler = (context: SecureApiContext) => Promise<NextResponse>;

type SecureApiOptions = {
  requireAuth?: boolean;
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

    let auth: AuthContext | null = null;
    if (options.requireAuth) {
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
    }

    const response = await handler({ auth });
    statusCode = response.status;
    return response;
  } catch (error) {
    errorMessage = error instanceof Error ? error.message : 'Unknown API error';
    statusCode = 500;

    return NextResponse.json(
      {
        ok: false,
        error: errorMessage,
      },
      { status: 500 }
    );
  } finally {
    const durationMs = Date.now() - startedAt;

    try {
      const route = new URL(request.url).pathname;
      await apiLogsStore.insert({
        route: routeName || route,
        method: request.method,
        statusCode,
        durationMs,
        userId,
        errorMessage,
      });
    } catch {
      // Logging failures should never break API responses.
    }
  }
}
