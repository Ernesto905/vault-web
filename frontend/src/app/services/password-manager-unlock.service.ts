import { Injectable } from '@angular/core';

const TOKEN_KEY = 'passwordManagerVaultToken';
const EXPIRES_AT_KEY = 'passwordManagerVaultTokenExpiresAt';

@Injectable({
  providedIn: 'root',
})
export class PasswordManagerUnlockService {
  getToken(): string | null {
    const token = sessionStorage.getItem(TOKEN_KEY);
    return token && token.length > 0 ? token : null;
  }

  getExpiresAt(): Date | null {
    const raw = sessionStorage.getItem(EXPIRES_AT_KEY);
    if (!raw) return null;
    const date = new Date(raw);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  isUnlocked(): boolean {
    const token = this.getToken();
    if (!token) return false;

    const expiresAt = this.getExpiresAt();
    if (!expiresAt) return true;

    return expiresAt.getTime() > Date.now();
  }

  setToken(token: string, expiresAt?: string | Date | null): void {
    sessionStorage.setItem(TOKEN_KEY, token);
    if (expiresAt == null) {
      sessionStorage.removeItem(EXPIRES_AT_KEY);
      return;
    }
    const date =
      typeof expiresAt === 'string' ? new Date(expiresAt) : expiresAt;

    if (Number.isNaN(date.getTime())) {
      sessionStorage.removeItem(EXPIRES_AT_KEY);
      return;
    }
    sessionStorage.setItem(EXPIRES_AT_KEY, date.toISOString());
  }

  clear(): void {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(EXPIRES_AT_KEY);
  }
}
