/**
 * Comprehensive error handling utility for OTA IDE
 */

export class OTAError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500,
    public context?: Record<string, any>
  ) {
    super(message);
    this.name = 'OTAError';
  }
}

export class ValidationError extends OTAError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'VALIDATION_ERROR', 400, context);
    this.name = 'ValidationError';
  }
}

export class NotFoundError extends OTAError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'NOT_FOUND', 404, context);
    this.name = 'NotFoundError';
  }
}

export class UnauthorizedError extends OTAError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'UNAUTHORIZED', 401, context);
    this.name = 'UnauthorizedError';
  }
}

export class ForbiddenError extends OTAError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'FORBIDDEN', 403, context);
    this.name = 'ForbiddenError';
  }
}

export class ConflictError extends OTAError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'CONFLICT', 409, context);
    this.name = 'ConflictError';
  }
}

export class NetworkError extends OTAError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'NETWORK_ERROR', 503, context);
    this.name = 'NetworkError';
  }
}

/**
 * Safe JSON parsing with error handling
 */
export function safeJsonParse<T = any>(json: string, fallback?: T): T {
  try {
    return JSON.parse(json);
  } catch (error) {
    console.error('[v0] JSON parse error:', error);
    if (fallback !== undefined) return fallback;
    throw new ValidationError('Invalid JSON format', { originalJson: json.slice(0, 100) });
  }
}

/**
 * Safe JSON stringify with error handling
 */
export function safeJsonStringify(obj: any, fallback = '{}'): string {
  try {
    return JSON.stringify(obj);
  } catch (error) {
    console.error('[v0] JSON stringify error:', error);
    return fallback;
  }
}

/**
 * Async error handler wrapper
 */
export function asyncHandler<T extends any[], R>(
  fn: (...args: T) => Promise<R>
) {
  return async (...args: T) => {
    try {
      return await fn(...args);
    } catch (error) {
      console.error('[v0] Async handler error:', error);
      throw error instanceof OTAError ? error : new OTAError(
        error instanceof Error ? error.message : 'Unknown error occurred',
        'ASYNC_ERROR',
        500,
        { originalError: error }
      );
    }
  };
}

/**
 * Retry handler with exponential backoff
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options = {
    maxRetries: 3,
    delayMs: 1000,
    backoffMultiplier: 2,
    shouldRetry: (error: any) => true,
  }
): Promise<T> {
  let lastError: any;
  let delay = options.delayMs;

  for (let attempt = 0; attempt <= options.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (attempt < options.maxRetries && options.shouldRetry(error)) {
        console.warn(`[v0] Retry attempt ${attempt + 1}/${options.maxRetries} after ${delay}ms`);
        await new Promise(resolve => setTimeout(resolve, delay));
        delay *= options.backoffMultiplier;
      } else {
        throw error;
      }
    }
  }

  throw lastError;
}

/**
 * Timeout handler
 */
export function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`Operation timed out after ${timeoutMs}ms`)), timeoutMs)
    ),
  ]);
}

/**
 * Error logger
 */
export function logError(error: any, context?: string) {
  const errorObj = {
    timestamp: new Date().toISOString(),
    context,
    message: error instanceof Error ? error.message : String(error),
    code: error instanceof OTAError ? error.code : 'UNKNOWN',
    stack: error instanceof Error ? error.stack : undefined,
    ...((error instanceof OTAError) && { errorContext: error.context }),
  };

  if (process.env.NODE_ENV === 'development') {
    console.error('[v0] Error logged:', errorObj);
  }

  // In production, could send to logging service
  return errorObj;
}

/**
 * Validate required fields
 */
export function validateRequired(obj: Record<string, any>, fields: string[]): void {
  const missing = fields.filter(field => !obj[field]);
  if (missing.length > 0) {
    throw new ValidationError(`Missing required fields: ${missing.join(', ')}`);
  }
}

/**
 * Validate object structure
 */
export function validateObject<T extends Record<string, any>>(
  obj: any,
  schema: Record<keyof T, 'string' | 'number' | 'boolean' | 'object' | 'array'>
): obj is T {
  for (const [key, type] of Object.entries(schema)) {
    const value = obj[key];
    const actualType = Array.isArray(value) ? 'array' : typeof value;
    
    if (actualType !== type) {
      throw new ValidationError(
        `Invalid type for field "${key}": expected ${type}, got ${actualType}`
      );
    }
  }
  return true;
}

/**
 * Safe array access with error handling
 */
export function safeArrayAccess<T>(array: T[], index: number, fallback?: T): T {
  if (index < 0 || index >= array.length) {
    if (fallback !== undefined) return fallback;
    throw new NotFoundError(`Array index ${index} out of bounds`, { arrayLength: array.length });
  }
  return array[index];
}

/**
 * Safe object access with error handling
 */
export function safeObjectAccess<T extends Record<string, any>, K extends keyof T>(
  obj: T,
  key: K,
  fallback?: T[K]
): T[K] {
  if (!(key in obj)) {
    if (fallback !== undefined) return fallback;
    throw new NotFoundError(`Property "${String(key)}" not found in object`);
  }
  return obj[key];
}
