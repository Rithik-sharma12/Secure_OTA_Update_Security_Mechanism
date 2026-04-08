/**
 * Standardized API response and error handling
 */

import { OTAError } from './error-handler';

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, any>;
  };
  timestamp: string;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination?: {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
  };
}

/**
 * Create successful response
 */
export function successResponse<T>(data: T, statusCode = 200): Response {
  const response: ApiResponse<T> = {
    success: true,
    data,
    timestamp: new Date().toISOString(),
  };

  return new Response(JSON.stringify(response), {
    status: statusCode,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Create paginated response
 */
export function paginatedResponse<T>(
  data: T[],
  page: number,
  pageSize: number,
  total: number,
  statusCode = 200
): Response {
  const totalPages = Math.ceil(total / pageSize);
  const response: PaginatedResponse<T> = {
    success: true,
    data,
    pagination: {
      page,
      pageSize,
      total,
      totalPages,
    },
    timestamp: new Date().toISOString(),
  };

  return new Response(JSON.stringify(response), {
    status: statusCode,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Create error response
 */
export function errorResponse(
  error: Error | OTAError | string,
  statusCode = 500
): Response {
  let code = 'INTERNAL_ERROR';
  let message = 'An internal error occurred';
  let details: Record<string, any> | undefined;

  if (error instanceof OTAError) {
    code = error.code;
    message = error.message;
    details = error.context;
    statusCode = error.statusCode;
  } else if (error instanceof Error) {
    message = error.message;
  } else {
    message = String(error);
  }

  const response: ApiResponse = {
    success: false,
    error: {
      code,
      message,
      details,
    },
    timestamp: new Date().toISOString(),
  };

  return new Response(JSON.stringify(response), {
    status: statusCode,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Validate request body
 */
export async function validateRequestBody<T>(
  request: Request,
  schema?: (data: any) => boolean
): Promise<T> {
  try {
    const body = await request.json();

    if (schema && !schema(body)) {
      throw new Error('Request validation failed');
    }

    return body as T;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid request body';
    throw new Error(message);
  }
}

/**
 * Get query parameter
 */
export function getQueryParam(url: string, param: string): string | null {
  try {
    const urlObj = new URL(url);
    return urlObj.searchParams.get(param);
  } catch {
    return null;
  }
}

/**
 * Get multiple query parameters
 */
export function getQueryParams(url: string): Record<string, string> {
  try {
    const urlObj = new URL(url);
    const params: Record<string, string> = {};

    urlObj.searchParams.forEach((value, key) => {
      params[key] = value;
    });

    return params;
  } catch {
    return {};
  }
}

/**
 * Handle API errors
 */
export function handleApiError(
  error: any,
  defaultMessage = 'An error occurred'
): Response {
  console.error('[v0] API Error:', error);

  if (error instanceof OTAError) {
    return errorResponse(error, error.statusCode);
  }

  if (error instanceof SyntaxError) {
    return errorResponse('Invalid JSON in request body', 400);
  }

  if (error instanceof TypeError && error.message.includes('fetch')) {
    return errorResponse('Network error', 503);
  }

  return errorResponse(error || defaultMessage, 500);
}

/**
 * API Handler wrapper with error handling
 */
export type ApiHandlerFn<T = any> = (
  request: Request,
  params?: Record<string, any>
) => Promise<Response>;

export function apiHandler(handler: ApiHandlerFn): ApiHandlerFn {
  return async (request: Request, params?: Record<string, any>) => {
    try {
      return await handler(request, params);
    } catch (error) {
      return handleApiError(error);
    }
  };
}

/**
 * Rate limiting headers
 */
export function addRateLimitHeaders(
  response: Response,
  remaining: number,
  limit: number,
  resetTime: number
): Response {
  response.headers.set('X-RateLimit-Limit', String(limit));
  response.headers.set('X-RateLimit-Remaining', String(remaining));
  response.headers.set('X-RateLimit-Reset', String(resetTime));
  return response;
}

/**
 * CORS headers
 */
export function addCorsHeaders(response: Response, origin = '*'): Response {
  response.headers.set('Access-Control-Allow-Origin', origin);
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  response.headers.set('Access-Control-Max-Age', '3600');
  return response;
}

/**
 * Cache control headers
 */
export function addCacheHeaders(
  response: Response,
  maxAge = 3600,
  isPublic = true
): Response {
  const cacheControl = `${isPublic ? 'public' : 'private'}, max-age=${maxAge}`;
  response.headers.set('Cache-Control', cacheControl);
  return response;
}

/**
 * Security headers
 */
export function addSecurityHeaders(response: Response): Response {
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  return response;
}

/**
 * Build complete response with all headers
 */
export function buildApiResponse<T>(
  data: T,
  options = {
    statusCode: 200,
    cacheMaxAge: 3600,
    isPublic: true,
    cors: true,
    security: true,
  }
): Response {
  let response = successResponse(data, options.statusCode);

  if (options.cacheMaxAge > 0) {
    response = addCacheHeaders(response, options.cacheMaxAge, options.isPublic);
  }

  if (options.cors) {
    response = addCorsHeaders(response);
  }

  if (options.security) {
    response = addSecurityHeaders(response);
  }

  return response;
}
