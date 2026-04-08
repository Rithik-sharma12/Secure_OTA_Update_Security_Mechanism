# Error Handling & Exception Management Guide

## Overview

This document outlines the comprehensive error handling and exception management system implemented in the OTA IDE application. The system provides utilities, components, and best practices for handling errors consistently across the application.

## Error Classes

### Base Error Classes

All custom errors extend the `OTAError` base class:

```typescript
import { 
  OTAError,
  ValidationError,
  NotFoundError,
  UnauthorizedError,
  ForbiddenError,
  ConflictError,
  NetworkError
} from '@/lib/error-handler';

// Validation errors (400)
throw new ValidationError('Invalid input', { field: 'email' });

// Not found errors (404)
throw new NotFoundError('Device not found', { deviceId: '123' });

// Unauthorized errors (401)
throw new UnauthorizedError('Authentication required');

// Forbidden errors (403)
throw new ForbiddenError('Access denied');

// Conflict errors (409)
throw new ConflictError('Resource already exists');

// Network errors (503)
throw new NetworkError('Service unavailable');
```

## Error Utilities

### Safe JSON Handling

```typescript
import { safeJsonParse, safeJsonStringify } from '@/lib/error-handler';

// Parse JSON with fallback
const data = safeJsonParse(jsonString, { default: 'value' });

// Stringify with error handling
const json = safeJsonStringify(obj, '{}');
```

### Async Error Handling

```typescript
import { asyncHandler, withRetry, withTimeout } from '@/lib/error-handler';

// Wrap async functions
const safeAsyncFn = asyncHandler(async (args) => {
  // function body
});

// Retry with exponential backoff
const data = await withRetry(
  () => fetchData(),
  {
    maxRetries: 3,
    delayMs: 1000,
    backoffMultiplier: 2,
  }
);

// Add timeout to promise
const result = await withTimeout(fetchData(), 5000);
```

### Validation Utilities

```typescript
import { 
  validateRequired,
  validateObject,
  safeArrayAccess,
  safeObjectAccess
} from '@/lib/error-handler';

// Validate required fields
validateRequired(obj, ['id', 'name']);

// Validate object structure
validateObject<MyType>(obj, {
  id: 'string',
  count: 'number',
  tags: 'array',
});

// Safe array access
const item = safeArrayAccess(array, 0, fallback);

// Safe object access
const value = safeObjectAccess(obj, 'key', 'default');
```

## Comprehensive Validation

Use the validation utilities for input validation:

```typescript
import { 
  validateEmail,
  validateVersion,
  validateIPAddress,
  validateInput
} from '@/lib/validation';

// Validate email
if (!validateEmail(email)) {
  throw new ValidationError('Invalid email format');
}

// Validate semantic version
if (!validateVersion('1.0.0')) {
  throw new ValidationError('Invalid version format');
}

// Validate IP address
if (!validateIPAddress('192.168.1.1')) {
  throw new ValidationError('Invalid IP address');
}

// Comprehensive input validation
validateInput(userInput, {
  required: true,
  type: 'string',
  minLength: 3,
  maxLength: 100,
  pattern: /^[a-z0-9]+$/,
  custom: (value) => customValidation(value),
});
```

## Error Boundary Component

Wrap components that might throw errors:

```typescript
import { ErrorBoundary } from '@/components/error/ErrorBoundary';
import { ErrorFallback } from '@/components/error/ErrorFallback';

export default function MyComponent() {
  return (
    <ErrorBoundary
      fallback={(error, reset) => (
        <ErrorFallback 
          error={error}
          resetError={reset}
          title="Custom Error Title"
          description="Custom error description"
        />
      )}
      onError={(error, errorInfo) => {
        // Log error or send to tracking service
        console.error('Component error:', error);
      }}
    >
      <YourComponent />
    </ErrorBoundary>
  );
}
```

## Hooks for Error Handling

### useErrorHandler

```typescript
import { useErrorHandler } from '@/hooks/useErrorHandler';

export function MyComponent() {
  const { error, isError, handleError, clearError } = useErrorHandler({
    context: 'MyComponent',
    onError: (error) => {
      // Handle error
    }
  });

  const handleAction = () => {
    try {
      // do something
    } catch (err) {
      handleError(err);
    }
  };

  return (
    <>
      {isError && <div>Error: {error?.message}</div>}
      <button onClick={handleAction}>Action</button>
      <button onClick={clearError}>Clear Error</button>
    </>
  );
}
```

### useAsync

```typescript
import { useAsync } from '@/hooks/useErrorHandler';

export function MyComponent() {
  const { data, isLoading, isError, error, execute } = useAsync(
    () => fetchData(),
    true, // immediate
    {
      context: 'fetchData',
      onSuccess: (data) => console.log('Success:', data),
      onError: (error) => console.error('Error:', error),
    }
  );

  if (isLoading) return <div>Loading...</div>;
  if (isError) return <div>Error: {error?.message}</div>;
  return <div>{JSON.stringify(data)}</div>;
}
```

### useFormValidation

```typescript
import { useFormValidation } from '@/hooks/useErrorHandler';

export function MyForm() {
  const { values, errors, touched, handleChange, handleBlur, validateForm } = 
    useFormValidation(
      { email: '', password: '' },
      (values) => {
        const errors: Record<string, string> = {};
        if (!values.email) errors.email = 'Email is required';
        if (!values.password) errors.password = 'Password is required';
        return errors;
      }
    );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (validateForm()) {
      // submit form
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input name="email" value={values.email} onChange={handleChange} onBlur={handleBlur} />
      {touched.email && errors.email && <div>{errors.email}</div>}
      <button type="submit">Submit</button>
    </form>
  );
}
```

## Logging & Monitoring

### Logger

```typescript
import { logger } from '@/lib/logger';

logger.debug('MyModule', 'Debug message', { data: 'value' });
logger.info('MyModule', 'Info message');
logger.warn('MyModule', 'Warning message');
logger.error('MyModule', 'Error message', error);

// Get logs
const allLogs = logger.getLogs();
const errorLogs = logger.getLogsByLevel('error');
const moduleLogs = logger.getLogsByContext('MyModule');

// Export logs
const logsText = logger.exportLogs();
```

### Performance Monitoring

```typescript
import { performanceMonitor } from '@/lib/logger';

// Manual timing
performanceMonitor.start('operation');
// do something
const duration = performanceMonitor.end('operation');

// Measure synchronous function
performanceMonitor.measure('operation', () => {
  // do something
});

// Measure async function
const result = await performanceMonitor.measureAsync('fetchData', async () => {
  return await fetchData();
});
```

### Error Tracking

```typescript
import { errorTracker } from '@/lib/logger';

try {
  // do something
} catch (error) {
  errorTracker.track(error, 'MyComponent');
}

// Get tracked errors
const errors = errorTracker.getErrors();
const componentErrors = errorTracker.getErrorsByContext('MyComponent');
const errorCount = errorTracker.getErrorCount();

// Export errors
const errorsJson = errorTracker.exportErrors();
```

## Global Error Handler

The application includes a global error handler page at `app/global-error.tsx` that catches unhandled errors at the application level. It displays a styled error page with:

- Error message and location
- Error stack trace (expandable)
- Retry and navigation buttons

## Best Practices

### 1. Always Handle Errors

```typescript
// ✓ Good
try {
  await operation();
} catch (error) {
  handleError(error);
}

// ✗ Bad
await operation(); // No error handling
```

### 2. Use Specific Error Types

```typescript
// ✓ Good
if (notFound) {
  throw new NotFoundError('Device not found');
}

// ✗ Bad
if (notFound) {
  throw new Error('Device not found');
}
```

### 3. Provide Context

```typescript
// ✓ Good
throw new ValidationError('Invalid device type', {
  deviceId: '123',
  providedType: type,
  allowedTypes: ['ESP32', 'STM32'],
});

// ✗ Bad
throw new ValidationError('Invalid device type');
```

### 4. Use Error Boundaries

```typescript
// ✓ Good
<ErrorBoundary>
  <RiskyComponent />
</ErrorBoundary>

// ✗ Bad
<RiskyComponent /> {/* No error boundary */}
```

### 5. Log Errors Appropriately

```typescript
// ✓ Good
logger.error('fetchData', 'Failed to fetch device', error, { deviceId: '123' });

// ✗ Bad
console.log(error); // Not structured
```

### 6. Validate Input

```typescript
// ✓ Good
validateInput(userEmail, {
  required: true,
  type: 'string',
  pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
});

// ✗ Bad
if (userEmail) { // Minimal validation
  // process
}
```

## Debugging with Console Logs

Use structured console logs for debugging:

```typescript
// ✓ Good
console.log("[v0] Component mounted with props:", props);
console.log("[v0] Fetching data from API...");

// ✗ Bad
console.log("test");
console.log(data);
```

## Error Handling in API Routes

```typescript
import { asyncHandler, ValidationError } from '@/lib/error-handler';
import { logger } from '@/lib/logger';

export const GET = asyncHandler(async (req) => {
  try {
    const data = await fetchData();
    return Response.json(data);
  } catch (error) {
    logger.error('GET /api/endpoint', 'Failed to fetch', error);
    
    if (error instanceof ValidationError) {
      return Response.json({ error: error.message }, { status: 400 });
    }
    
    return Response.json({ error: 'Internal server error' }, { status: 500 });
  }
});
```

## Testing Error Handling

```typescript
import { ValidationError } from '@/lib/error-handler';

describe('Error handling', () => {
  it('should throw ValidationError for invalid input', () => {
    expect(() => {
      validateRequired({}, ['id']);
    }).toThrow(ValidationError);
  });

  it('should catch and handle errors', async () => {
    const handleError = jest.fn();
    const { result } = renderHook(() => useErrorHandler({ onError: handleError }));
    
    result.current.handleError(new Error('test error'));
    
    expect(handleError).toHaveBeenCalled();
  });
});
```

## Summary

The error handling system provides:

- **Typed Errors**: Specific error classes for different scenarios
- **Utilities**: Safe operations and validation functions
- **Components**: Error boundaries and fallback UIs
- **Hooks**: Convenient error handling in React components
- **Logging**: Structured logging with performance monitoring
- **Global Handler**: Catches application-level errors

Use these tools consistently throughout the application to ensure robust error handling and better debugging experiences.
