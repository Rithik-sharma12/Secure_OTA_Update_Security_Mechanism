/**
 * Comprehensive logging utility for OTA IDE
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  context: string;
  message: string;
  data?: any;
  stack?: string;
}

class Logger {
  private logs: LogEntry[] = [];
  private maxLogs = 1000;
  private isDevelopment = process.env.NODE_ENV === 'development';

  private createLogEntry(
    level: LogLevel,
    context: string,
    message: string,
    data?: any
  ): LogEntry {
    return {
      timestamp: new Date().toISOString(),
      level,
      context,
      message,
      data,
    };
  }

  private formatLogMessage(entry: LogEntry): string {
    return `[${entry.timestamp}] [${entry.level.toUpperCase()}] [${entry.context}] ${entry.message}`;
  }

  private outputLog(entry: LogEntry): void {
    const formatted = this.formatLogMessage(entry);

    switch (entry.level) {
      case 'debug':
        if (this.isDevelopment) console.debug(formatted, entry.data || '');
        break;
      case 'info':
        console.log(formatted, entry.data || '');
        break;
      case 'warn':
        console.warn(formatted, entry.data || '');
        break;
      case 'error':
        console.error(formatted, entry.data || '');
        break;
    }
  }

  debug(context: string, message: string, data?: any): void {
    const entry = this.createLogEntry('debug', context, message, data);
    this.logs.push(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }
    this.outputLog(entry);
  }

  info(context: string, message: string, data?: any): void {
    const entry = this.createLogEntry('info', context, message, data);
    this.logs.push(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }
    this.outputLog(entry);
  }

  warn(context: string, message: string, data?: any): void {
    const entry = this.createLogEntry('warn', context, message, data);
    this.logs.push(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }
    this.outputLog(entry);
  }

  error(context: string, message: string, error?: Error | any, data?: any): void {
    const entry: LogEntry = {
      ...this.createLogEntry('error', context, message, data),
      stack: error instanceof Error ? error.stack : undefined,
    };
    this.logs.push(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }
    this.outputLog(entry);
  }

  getLogs(): LogEntry[] {
    return [...this.logs];
  }

  getLogsByLevel(level: LogLevel): LogEntry[] {
    return this.logs.filter(log => log.level === level);
  }

  getLogsByContext(context: string): LogEntry[] {
    return this.logs.filter(log => log.context === context);
  }

  clearLogs(): void {
    this.logs = [];
  }

  exportLogs(): string {
    return this.logs.map(entry => this.formatLogMessage(entry)).join('\n');
  }
}

// Export singleton instance
export const logger = new Logger();

/**
 * Performance monitoring utility
 */
export class PerformanceMonitor {
  private marks: Map<string, number> = new Map();

  start(label: string): void {
    this.marks.set(label, performance.now());
  }

  end(label: string): number {
    const startTime = this.marks.get(label);
    if (!startTime) {
      console.warn(`Performance mark "${label}" not found`);
      return 0;
    }

    const duration = performance.now() - startTime;
    this.marks.delete(label); // Clear the mark after ending

    logger.debug('Performance', `${label} took ${duration.toFixed(2)}ms`);

    return duration;
  }

  measure(label: string, fn: () => void): number {
    this.start(label);
    fn();
    return this.end(label);
  }

  async measureAsync<T>(label: string, fn: () => Promise<T>): Promise<T> {
    this.start(label);
    const result = await fn();
    this.end(label);
    return result;
  }
}

export const performanceMonitor = new PerformanceMonitor();

/**
 * Error tracking utility
 */
export class ErrorTracker {
  private errors: any[] = [];
  private maxErrors = 100;

  track(error: any, context?: string): void {
    const errorEntry = {
      timestamp: new Date().toISOString(),
      context,
      message: error instanceof Error ? error.message : String(error),
      type: error?.constructor?.name || 'Unknown',
      stack: error instanceof Error ? error.stack : undefined,
    };

    this.errors.push(errorEntry);
    if (this.errors.length > this.maxErrors) {
      this.errors.shift();
    }

    logger.error('ErrorTracker', `Error tracked: ${errorEntry.message}`, error, { context });
  }

  getErrors(): any[] {
    return [...this.errors];
  }

  getErrorsByContext(context: string): any[] {
    return this.errors.filter(err => err.context === context);
  }

  getErrorCount(): number {
    return this.errors.length;
  }

  clearErrors(): void {
    this.errors = [];
  }

  exportErrors(): string {
    return JSON.stringify(this.errors, null, 2);
  }
}

export const errorTracker = new ErrorTracker();
