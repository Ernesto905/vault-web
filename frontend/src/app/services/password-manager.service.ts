import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { PasswordEntryDto } from '../models/dtos/PasswordEntryDto';
import { PasswordEntryCreateRequestDto } from '../models/dtos/PasswordEntryCreateRequestDto';
import { PasswordRevealResponseDto } from '../models/dtos/PasswordRevealResponseDto';
import { PasswordManagerUnlockService } from './password-manager-unlock.service';

@Injectable({
  providedIn: 'root',
})
export class PasswordManagerService {
  private apiUrl = environment.passwordManagerApiUrl;

  constructor(
    private http: HttpClient,
    private unlockService: PasswordManagerUnlockService,
  ) {}

  private buildAuthHeaders(): HttpHeaders | undefined {
    const token = this.unlockService.getToken();
    if (!token) return undefined;
    return new HttpHeaders({ 'X-Vault-Token': token });
  }

  getAll(): Observable<PasswordEntryDto[]> {
    const headers = this.buildAuthHeaders();
    return this.http.get<PasswordEntryDto[]>(`${this.apiUrl}/passwords`, {
      headers,
    });
  }

  create(payload: PasswordEntryCreateRequestDto): Observable<PasswordEntryDto> {
    const headers = this.buildAuthHeaders();
    return this.http.post<PasswordEntryDto>(
      `${this.apiUrl}/passwords`,
      payload,
      {
        headers,
      },
    );
  }

  update(
    id: number,
    payload: PasswordEntryCreateRequestDto,
  ): Observable<PasswordEntryDto> {
    const headers = this.buildAuthHeaders();
    return this.http.put<PasswordEntryDto>(
      `${this.apiUrl}/passwords/${id}`,
      payload,
      {
        headers,
      },
    );
  }

  delete(id: number): Observable<void> {
    const headers = this.buildAuthHeaders();
    return this.http.delete<void>(`${this.apiUrl}/passwords/${id}`, {
      headers,
    });
  }

  reveal(id: number): Observable<PasswordRevealResponseDto> {
    const headers = this.buildAuthHeaders();
    return this.http.post<PasswordRevealResponseDto>(
      `${this.apiUrl}/passwords/${id}/reveal`,
      null,
      { headers },
    );
  }

  revealLegacyGet(id: number): Observable<PasswordRevealResponseDto> {
    const headers = this.buildAuthHeaders();
    return this.http.get<PasswordRevealResponseDto>(
      `${this.apiUrl}/passwords/${id}/reveal`,
      { headers },
    );
  }
}
