import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';

export interface ActivityLogEntry {
  timestamp: string;
  action: string;
  component: string;
  details?: Record<string, unknown>;
  result?: 'success' | 'failure' | 'pending';
  errorMessage?: string;
}

export interface ActivityLog {
  sessionId: string;
  sessionStart: string;
  appVersion: string;
  entries: ActivityLogEntry[];
}

export class UserActivityLogger {
  private readonly LOG_DIR: string;
  private currentLog: ActivityLog;
  private logFilePath: string;

  constructor() {
    // Store logs in userData directory (portable across machines)
    const baseDir = app.getPath('userData');
    this.LOG_DIR = path.join(baseDir, 'logs', 'user-activity');

    // Ensure log directory exists
    if (!fs.existsSync(this.LOG_DIR)) {
      fs.mkdirSync(this.LOG_DIR, { recursive: true });
    }

    // Initialize session
    const sessionId = this.generateSessionId();
    const sessionStart = new Date().toISOString();

    this.currentLog = {
      sessionId,
      sessionStart,
      appVersion: '2.0.0',
      entries: [],
    };

    // Create log file with timestamp
    const dateStr = new Date().toISOString().split('T')[0];
    const timeStr = new Date().toISOString().split('T')[1].substring(0, 8).replace(/:/g, '-');
    this.logFilePath = path.join(this.LOG_DIR, `session-${dateStr}-${timeStr}-${sessionId.substring(0, 8)}.json`);

    // Log session start
    this.log('session_start', 'System', { sessionId });

    console.log(`[UserActivityLogger] Session started: ${sessionId}`);
    console.log(`[UserActivityLogger] Log file: ${this.logFilePath}`);
  }

  private generateSessionId(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  /**
   * Log a user action
   */
  log(
    action: string,
    component: string,
    details?: Record<string, unknown>,
    result?: 'success' | 'failure' | 'pending',
    errorMessage?: string
  ): void {
    const entry: ActivityLogEntry = {
      timestamp: new Date().toISOString(),
      action,
      component,
      details,
      result,
      errorMessage,
    };

    this.currentLog.entries.push(entry);
    this.saveLog();

    // Also log to console for debugging
    const logLevel = result === 'failure' ? 'error' : 'log';
    console[logLevel](
      `[UserActivity] ${entry.timestamp} | ${component} | ${action}` +
        (result ? ` | ${result}` : '') +
        (errorMessage ? ` | ${errorMessage}` : '')
    );
  }

  /**
   * Log a successful action
   */
  logSuccess(action: string, component: string, details?: Record<string, unknown>): void {
    this.log(action, component, details, 'success');
  }

  /**
   * Log a failed action
   */
  logFailure(action: string, component: string, errorMessage: string, details?: Record<string, unknown>): void {
    this.log(action, component, details, 'failure', errorMessage);
  }

  /**
   * Log navigation
   */
  logNavigation(from: string, to: string): void {
    this.log('navigation', 'App', { from, to }, 'success');
  }

  /**
   * Log button click
   */
  logClick(buttonName: string, component: string, details?: Record<string, unknown>): void {
    this.log('button_click', component, { button: buttonName, ...details });
  }

  /**
   * Log input change (without sensitive data)
   */
  logInput(inputName: string, component: string, valueLength?: number): void {
    this.log('input_change', component, {
      input: inputName,
      valueLength: valueLength ?? 0,
      // Never log actual values for security
    });
  }

  /**
   * Get current session log
   */
  getSessionLog(): ActivityLog {
    return { ...this.currentLog };
  }

  /**
   * Get log file path
   */
  getLogFilePath(): string {
    return this.logFilePath;
  }

  /**
   * Export current log to a specific path
   */
  exportLog(outputPath: string): void {
    fs.writeFileSync(outputPath, JSON.stringify(this.currentLog, null, 2), 'utf-8');
    console.log(`[UserActivityLogger] Log exported to: ${outputPath}`);
  }

  /**
   * Save log to file
   */
  private saveLog(): void {
    try {
      fs.writeFileSync(this.logFilePath, JSON.stringify(this.currentLog, null, 2), 'utf-8');
    } catch (error) {
      console.error(`[UserActivityLogger] Failed to save log: ${(error as Error).message}`);
    }
  }

  /**
   * End session
   */
  endSession(): void {
    this.log('session_end', 'System', {
      totalEntries: this.currentLog.entries.length,
      duration: this.calculateDuration(),
    });
    console.log(`[UserActivityLogger] Session ended. Log saved to: ${this.logFilePath}`);
  }

  private calculateDuration(): string {
    const start = new Date(this.currentLog.sessionStart);
    const end = new Date();
    const diffMs = end.getTime() - start.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffSecs = Math.floor((diffMs % 60000) / 1000);
    return `${diffMins}m ${diffSecs}s`;
  }
}

// Singleton instance
let loggerInstance: UserActivityLogger | null = null;

export function getActivityLogger(): UserActivityLogger {
  if (!loggerInstance) {
    loggerInstance = new UserActivityLogger();
  }
  return loggerInstance;
}
