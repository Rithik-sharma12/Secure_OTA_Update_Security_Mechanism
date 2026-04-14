import { NextResponse } from 'next/server';
import { loginWithPassword, SESSION_COOKIE_NAME } from '@/lib/auth';
import { errorResponse } from '@/lib/api-response';
import { logger, errorTracker } from '@/lib/logger';
import { OTAError } from '@/lib/error-handler';

export async function POST(request: Request) {
  try {
    const { username, password } = await request.json();

    const authResult = await loginWithPassword(username, password);

    if (!authResult) {
      return errorResponse('Invalid credentials', 401);
    }

    const { sessionToken, expiresAt, user } = authResult;

    // Create a response and set the HttpOnly cookie
    const response = NextResponse.json({
      success: true,
      data: { user }, // Only send public user data to client
      timestamp: new Date().toISOString(),
    }, { status: 200 });

    response.cookies.set({
      name: SESSION_COOKIE_NAME,
      value: sessionToken,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use secure in production
      sameSite: 'lax',
      expires: new Date(expiresAt),
      path: '/',
    });

    return response;

  } catch (error: unknown) {
    logger.error('AuthAPI', 'Login failed', error);
    errorTracker.track(error, 'AuthAPI:Login');
    if (error instanceof OTAError) {
      return errorResponse(error, error.statusCode);
    }
    return errorResponse('An unexpected error occurred during login', 500);
  }
}