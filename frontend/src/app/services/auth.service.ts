import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { map, Observable, tap } from 'rxjs';
import { environment } from '../../environments/environment';
import { Router } from '@angular/router';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private apiUrl = environment.mainApiUrl;

  constructor(private http: HttpClient,
     private router: Router 
  ) {}

  login(username: string, password: string): Observable<{ token: string }> {
    return this.http
      .post<{
        token: string;
      }>(`${this.apiUrl}/auth/login`, { username, password })
      .pipe(
        tap((res) => {
          this.saveToken(res.token);
          this.saveUsername(username);
        }),
      );
  }

  register(username: string, password: string): Observable<string> {
    return this.http.post(
      `${this.apiUrl}/auth/register`,
      { username, password },
      { responseType: 'text' },
    );
  }

  saveToken(token: string): void {
    localStorage.setItem('token', token);
  }

  saveUsername(username: string): void {
    localStorage.setItem('username', username);
  }

  getToken(): string | null {
    return localStorage.getItem('token') as string | null;
  }

  getUsername(): string | null {
    return localStorage.getItem('username') as string | null;
  }

  isLoggedIn(): boolean {
    return !!localStorage.getItem('token');
  }

  logout(): void {
    localStorage.removeItem('token');
    localStorage.removeItem('username');

    this.router.navigate(['/login']);
  }

  checkUsernameExists(username: string): Observable<boolean> {
    return this.http
      .get<{
        exists: boolean;
      }>(`${this.apiUrl}/auth/check-username`, { params: { username } })
      .pipe(map((response) => response.exists));
  }
}
