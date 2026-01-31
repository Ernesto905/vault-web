import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface VaultStatusResponseDto {
  initialized: boolean;
}

export interface VaultUnlockResponseDto {
  token: string;
  expiresAt: string;
}

@Injectable({
  providedIn: 'root',
})
export class PasswordManagerVaultService {
  private apiUrl = environment.passwordManagerApiUrl;

  constructor(private http: HttpClient) {}

  status(): Observable<VaultStatusResponseDto> {
    return this.http.get<VaultStatusResponseDto>(`${this.apiUrl}/vault/status`);
  }

  setup(masterPassword: string): Observable<void> {
    return this.http.post<void>(`${this.apiUrl}/vault/setup`, {
      masterPassword,
    });
  }

  unlock(masterPassword: string): Observable<VaultUnlockResponseDto> {
    return this.http.post<VaultUnlockResponseDto>(
      `${this.apiUrl}/vault/unlock`,
      {
        masterPassword,
      },
    );
  }

  lock(vaultToken: string | null): Observable<void> {
    const headers = vaultToken
      ? new HttpHeaders({ 'X-Vault-Token': vaultToken })
      : undefined;
    return this.http.post<void>(`${this.apiUrl}/vault/lock`, null, { headers });
  }

  migrate(vaultToken: string): Observable<{ migratedCount: number }> {
    const headers = new HttpHeaders({ 'X-Vault-Token': vaultToken });
    return this.http.post<{ migratedCount: number }>(
      `${this.apiUrl}/vault/migrate`,
      null,
      {
        headers,
      },
    );
  }
}
