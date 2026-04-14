import { NextResponse } from 'next/server';
import { revokeRequestToken, SESSION_COOKIE_NAME } from '@/lib/auth';
import { errorResponse } from '@/lib/api-response';
import { logger, errorTracker } from '@/lib/logger';
import { OTAError } from '@/lib/error-handler';

export async function POST(request: Request) {
  try {
    await revokeRequestToken(request);

    // Create a response and clear the HttpOnly cookie
    const response = NextResponse.json({
      success: true,
      message: 'Logged out successfully',
      timestamp: new Date().toISOString(),
    }, { status: 200 });

    response.cookies.delete(SESSION_COOKIE_NAME);

    return response;

  } catch (error: unknown) {
    logger.error('AuthAPI', 'Logout failed', error);
    errorTracker.track(error, 'AuthAPI:Logout');
    if (error instanceof OTAError) {
      return errorResponse(error, error.statusCode);
    }
    return errorResponse('An unexpected error occurred during logout', 500);
  }
}