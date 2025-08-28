import { Injectable } from '@angular/core';
import { environment } from '../../environments/environment';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { UserDto } from '../models/dtos/UserDto';

@Injectable({
  providedIn: 'root',
})
export class UserService {
  private apiUrl = environment.mainApiUrl;

  constructor(private http: HttpClient) {}

  getAllUsers(): Observable<UserDto[]> {
    return this.http.get<UserDto[]>(`${this.apiUrl}/auth/users`);
  }
}
