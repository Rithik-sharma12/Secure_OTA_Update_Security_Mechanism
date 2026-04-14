/**
 * Comprehensive validation utilities for OTA IDE
 */
import { logger, errorTracker } from './logger';

import { ValidationError } from './error-handler';

/**
 * Validate email address
 */
export function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate semantic version
 */
export function validateVersion(version: string): boolean {
  const versionRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$/;
  return versionRegex.test(version);
}

/**
 * Validate device MAC address
 */
export function validateMACAddress(mac: string): boolean {
  const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
  return macRegex.test(mac);
}

/**
 * Validate IP address
 */
export function validateIPAddress(ip: string): boolean {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip)) return false;
  
  const parts = ip.split('.');
  return parts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
}

/**
 * Validate URL
 */
export function validateURL(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate JSON string
 */
export function validateJSON(json: string): boolean {
  try {
    JSON.parse(json);
    return true;
  } catch (error: unknown) {
    logger.debug('Validation', 'Invalid JSON string', error);
    return false;
  }
}

/**
 * Validate string length
 */
export function validateStringLength(
  str: string,
  minLength?: number,
  maxLength?: number
): boolean {
  if (minLength !== undefined && str.length < minLength) return false;
  if (maxLength !== undefined && str.length > maxLength) return false;
  return true;
}

/**
 * Validate number range
 */
export function validateNumberRange(
  num: number,
  min?: number,
  max?: number
): boolean {
  if (min !== undefined && num < min) return false;
  if (max !== undefined && num > max) return false;
  return true;
}

/**
 * Validate array is not empty
 */
export function validateNonEmptyArray<T>(arr: T[]): boolean {
  return Array.isArray(arr) && arr.length > 0;
}

/**
 * Validate object has properties
 */
export function validateObjectProperties<T extends Record<string, any>>(
  obj: T,
  requiredProperties: (keyof T)[]
): boolean {
  return requiredProperties.every(prop => prop in obj && obj[prop] !== undefined && obj[prop] !== null);
}

/**
 * Validate device type
 */
export function validateDeviceType(type: string): boolean {
  const validTypes = ['ATmega328P', 'ESP8266', 'ESP32', 'STM32F103'];
  return validTypes.includes(type);
}

/**
 * Validate firmware filename
 */
export function validateFirmwareFilename(filename: string): boolean {
  const firmwareRegex = /^[\w\-\.]+\.bin$/i;
  return firmwareRegex.test(filename);
}

/**
 * Validate and sanitize input
 */
export function sanitizeInput(input: string, maxLength = 1000): string {
  if (!validateStringLength(input, 0, maxLength)) {
    throw new ValidationError(`Input exceeds maximum length of ${maxLength} characters`);
  }
  
  // Remove potentially harmful characters
  return input
    .replace(/[<>]/g, '')
    .trim();
}

/**
 * Validate and parse device config
 */
export function validateDeviceConfig(config: any): {
  id: string;
  type: string;
  name: string;
  firmware_version: string;
} {
  const requiredFields = ['id', 'type', 'name', 'firmware_version'];
  
  if (!validateObjectProperties(config, requiredFields as any)) {
    throw new ValidationError('Device config missing required fields', { config });
  }
  
  if (!validateDeviceType(config.type)) {
    throw new ValidationError(`Invalid device type: ${config.type}`);
  }
  
  if (!validateVersion(config.firmware_version)) {
    throw new ValidationError(`Invalid firmware version: ${config.firmware_version}`);
  }
  
  return config;
}

/**
 * Validate and parse manifest
 */
export function validateManifest(manifest: any): boolean {
  const requiredFields = ['id', 'entries', 'signature', 'createdAt'];
  
  if (!validateObjectProperties(manifest, requiredFields as any)) {
    throw new ValidationError('Manifest missing required fields');
  }
  
  if (!validateNonEmptyArray(manifest.entries)) {
    throw new ValidationError('Manifest must contain at least one entry');
  }
  
  manifest.entries.forEach((entry: any, index: number) => {
    if (!entry.device_id || !entry.version) {
      throw new ValidationError(`Invalid manifest entry at index ${index}`);
    }
  });
  
  return true;
}

/**
 * Validate file upload
 */
export function validateFileUpload(
  file: File,
  options = {
    maxSize: 100 * 1024 * 1024, // 100MB
    allowedTypes: ['application/octet-stream', 'application/x-binary'],
  }
): boolean {
  if (file.size > options.maxSize) {
    throw new ValidationError(`File size exceeds ${options.maxSize} bytes`);
  }
  
  if (!options.allowedTypes.includes(file.type)) {
    throw new ValidationError(`File type ${file.type} is not allowed`);
  }
  
  return true;
}

/**
 * Comprehensive input validation helper
 */
export function validateInput(
  value: any,
  rules: {
    required?: boolean;
    type?: 'string' | 'number' | 'boolean' | 'array' | 'object';
    minLength?: number;
    maxLength?: number;
    min?: number;
    max?: number;
    pattern?: RegExp;
    custom?: (value: any) => boolean;
  }
): boolean {
  // Check required
  if (rules.required && (value === undefined || value === null || value === '')) {
    throw new ValidationError('This field is required');
  }
  
  // Check type
  if (rules.type) {
    const actualType = Array.isArray(value) ? 'array' : typeof value;
    if (actualType !== rules.type) {
      throw new ValidationError(`Expected type ${rules.type}, got ${actualType}`);
    }
  }
  
  // Check string length
  if (typeof value === 'string') {
    if (rules.minLength !== undefined && value.length < rules.minLength) {
      throw new ValidationError(`Minimum length is ${rules.minLength} characters`);
    }
    if (rules.maxLength !== undefined && value.length > rules.maxLength) {
      throw new ValidationError(`Maximum length is ${rules.maxLength} characters`);
    }
  }
  
  // Check number range
  if (typeof value === 'number') {
    if (rules.min !== undefined && value < rules.min) {
      throw new ValidationError(`Minimum value is ${rules.min}`);
    }
    if (rules.max !== undefined && value > rules.max) {
      throw new ValidationError(`Maximum value is ${rules.max}`);
    }
  }
  
  // Check pattern
  if (rules.pattern && typeof value === 'string' && !rules.pattern.test(value)) {
    throw new ValidationError('Invalid format');
  }
  
  // Check custom validator
  if (rules.custom && !rules.custom(value)) {
    throw new ValidationError('Validation failed');
  }
  
  return true;
}
