import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs/internal/Observable';
import { PrivateChatDto } from '../models/dtos/PrivateChatDto';
import { environment } from '../../environments/environment.test';
import { ChatMessageDto } from '../models/dtos/ChatMessageDto';

@Injectable({
  providedIn: 'root',
})
export class PrivateChatService {
  private apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}

  getOrCreatePrivateChat(
    username1: string,
    username2: string,
  ): Observable<PrivateChatDto> {
    return this.http.get<PrivateChatDto>(
      `${this.apiUrl}/private-chats/between?sender=${username1}&receiver=${username2}`,
    );
  }

  getMessages(privateChatId: number): Observable<ChatMessageDto[]> {
    return this.http.get<ChatMessageDto[]>(
      `${this.apiUrl}/private-chats/private?privateChatId=${privateChatId}`,
    );
  }
}
