import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

export const WS = 'ws://localhost:8000/ws/cases';

@Injectable({ providedIn: 'root' })
export class FeedService {
  connect(): Observable<any> {
    return new Observable((sub) => {
      const ws = new WebSocket(WS);
      ws.onmessage = (e) => sub.next(JSON.parse(e.data));
      ws.onerror = (e) => sub.error(e);
      return () => ws.close();
    });
  }
}
