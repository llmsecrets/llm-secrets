import * as keytar from 'keytar';

export type AutoLockInterval = 5 | 10 | 30 | 0; // 0 = never

export interface AutoLockState {
  enabled: boolean;
  intervalMinutes: AutoLockInterval;
  lastActivity: number;
  isLocked: boolean;
}

export class AutoLockService {
  private readonly SERVICE_NAME = 'scrt-electron';
  private readonly SETTINGS_KEY = 'autolock_settings';
  private timer: NodeJS.Timeout | null = null;
  private state: AutoLockState;
  private onLockCallback: (() => void) | null = null;

  constructor() {
    this.state = {
      enabled: false,
      intervalMinutes: 5,
      lastActivity: Date.now(),
      isLocked: false,
    };
  }

  /**
   * Initialize the auto-lock service and load saved settings
   */
  async initialize(): Promise<void> {
    await this.loadSettings();
    if (this.state.enabled && this.state.intervalMinutes > 0) {
      this.startTimer();
    }
  }

  /**
   * Register a callback to be called when auto-lock triggers
   */
  onLock(callback: () => void): void {
    this.onLockCallback = callback;
  }

  /**
   * Record user activity to reset the inactivity timer
   */
  recordActivity(): void {
    this.state.lastActivity = Date.now();
    if (this.state.isLocked) {
      this.state.isLocked = false;
    }
  }

  /**
   * Set the auto-lock interval (in minutes)
   * @param minutes - 5, 10, 30, or 0 (never)
   */
  async setInterval(minutes: AutoLockInterval): Promise<void> {
    this.state.intervalMinutes = minutes;
    this.state.enabled = minutes > 0;

    // Restart timer with new interval
    this.stopTimer();
    if (this.state.enabled) {
      this.startTimer();
    }

    await this.saveSettings();
  }

  /**
   * Get current auto-lock settings
   */
  getSettings(): AutoLockState {
    return { ...this.state };
  }

  /**
   * Check if currently locked
   */
  isLocked(): boolean {
    return this.state.isLocked;
  }

  /**
   * Manually trigger lock
   */
  lock(): void {
    this.state.isLocked = true;
    if (this.onLockCallback) {
      this.onLockCallback();
    }
  }

  /**
   * Unlock (requires successful decryption)
   */
  unlock(): void {
    this.state.isLocked = false;
    this.recordActivity();
  }

  /**
   * Get time remaining until auto-lock (in seconds)
   */
  getTimeRemaining(): number {
    if (!this.state.enabled || this.state.intervalMinutes === 0) {
      return -1; // Never
    }

    const elapsed = Date.now() - this.state.lastActivity;
    const intervalMs = this.state.intervalMinutes * 60 * 1000;
    const remaining = Math.max(0, intervalMs - elapsed);

    return Math.floor(remaining / 1000);
  }

  /**
   * Clean up resources
   */
  destroy(): void {
    this.stopTimer();
    this.onLockCallback = null;
  }

  private startTimer(): void {
    if (this.timer) {
      this.stopTimer();
    }

    // Check every 10 seconds
    this.timer = setInterval(() => {
      this.checkInactivity();
    }, 10000);
  }

  private stopTimer(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private checkInactivity(): void {
    if (!this.state.enabled || this.state.intervalMinutes === 0) {
      return;
    }

    const elapsed = Date.now() - this.state.lastActivity;
    const intervalMs = this.state.intervalMinutes * 60 * 1000;

    if (elapsed >= intervalMs && !this.state.isLocked) {
      this.lock();
    }
  }

  private async loadSettings(): Promise<void> {
    try {
      const settingsJson = await keytar.getPassword(this.SERVICE_NAME, this.SETTINGS_KEY);
      if (settingsJson) {
        const saved = JSON.parse(settingsJson);
        this.state.enabled = saved.enabled ?? false;
        this.state.intervalMinutes = saved.intervalMinutes ?? 5;
      }
    } catch (error) {
      console.error('Failed to load auto-lock settings:', error);
    }
  }

  private async saveSettings(): Promise<void> {
    try {
      const settings = {
        enabled: this.state.enabled,
        intervalMinutes: this.state.intervalMinutes,
      };
      await keytar.setPassword(this.SERVICE_NAME, this.SETTINGS_KEY, JSON.stringify(settings));
    } catch (error) {
      console.error('Failed to save auto-lock settings:', error);
    }
  }
}
