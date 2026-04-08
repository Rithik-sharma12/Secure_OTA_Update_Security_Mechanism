import { useState, useCallback } from 'react';
import { OTAError, logError } from '@/lib/error-handler';

interface UseErrorHandlerOptions {
  onError?: (error: any) => void;
  context?: string;
}

export function useErrorHandler(options?: UseErrorHandlerOptions) {
  const [error, setError] = useState<Error | null>(null);
  const [isError, setIsError] = useState(false);

  const handleError = useCallback((err: any) => {
    const errorObj = err instanceof Error ? err : new Error(String(err));
    
    // Log error
    logError(errorObj, options?.context);
    
    // Set state
    setError(errorObj);
    setIsError(true);
    
    // Call custom handler if provided
    options?.onError?.(errorObj);
  }, [options?.context, options?.onError]);

  const clearError = useCallback(() => {
    setError(null);
    setIsError(false);
  }, []);

  return {
    error,
    isError,
    handleError,
    clearError,
  };
}

interface UseAsyncOptions {
  onError?: (error: any) => void;
  onSuccess?: (data: any) => void;
  context?: string;
}

export function useAsync<T, E = Error>(
  asyncFunction: () => Promise<T>,
  immediate = true,
  options?: UseAsyncOptions
) {
  const [status, setStatus] = useState<'idle' | 'pending' | 'success' | 'error'>('idle');
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<E | null>(null);

  const execute = useCallback(async () => {
    setStatus('pending');
    setData(null);
    setError(null);

    try {
      const response = await asyncFunction();
      setData(response);
      setStatus('success');
      options?.onSuccess?.(response);
      return response;
    } catch (err) {
      const errorObj = err as E;
      setError(errorObj);
      setStatus('error');
      
      // Log error
      logError(errorObj, options?.context);
      
      // Call error handler
      options?.onError?.(errorObj);
      
      throw errorObj;
    }
  }, [asyncFunction, options?.onError, options?.onSuccess, options?.context]);

  // Run immediately if requested
  React.useEffect(() => {
    if (immediate) {
      execute();
    }
  }, [execute, immediate]);

  return {
    execute,
    status,
    data,
    error,
    isLoading: status === 'pending',
    isError: status === 'error',
    isSuccess: status === 'success',
  };
}

import React from 'react';

interface UseFormValidationOptions {
  onValidationError?: (errors: Record<string, string>) => void;
}

export function useFormValidation<T extends Record<string, any>>(
  initialValues: T,
  validate: (values: T) => Record<string, string>,
  options?: UseFormValidationOptions
) {
  const [values, setValues] = useState(initialValues);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [touched, setTouched] = useState<Record<string, boolean>>({});

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setValues(prev => ({ ...prev, [name]: value }));
  }, []);

  const handleBlur = useCallback((e: React.FocusEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name } = e.target;
    setTouched(prev => ({ ...prev, [name]: true }));
  }, []);

  const validateForm = useCallback(() => {
    const newErrors = validate(values);
    setErrors(newErrors);
    
    if (Object.keys(newErrors).length > 0) {
      options?.onValidationError?.(newErrors);
    }
    
    return Object.keys(newErrors).length === 0;
  }, [values, validate, options?.onValidationError]);

  const reset = useCallback(() => {
    setValues(initialValues);
    setErrors({});
    setTouched({});
  }, [initialValues]);

  return {
    values,
    errors,
    touched,
    handleChange,
    handleBlur,
    validateForm,
    reset,
    setValues,
    setErrors,
  };
}
