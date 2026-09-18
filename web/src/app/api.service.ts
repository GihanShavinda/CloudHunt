import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { API } from './auth.service';

export interface ManagedUser {
  username: string;
  email?: string | null;
  role: 'administrator' | 'cloud_analyst' | 'viewer';
  mfa_enabled: boolean;
  disabled: boolean;
}

@Injectable({ providedIn: 'root' })
export class ApiService {
  constructor(private http: HttpClient) {}

  dashboard(): Observable<any> {
    return this.http.get<any>(`${API}/dashboard/summary`);
  }

  cases(): Observable<any> {
    return this.http.get<any>(`${API}/cases`);
  }

  caseDetail(id: string): Observable<any> {
    return this.http.get<any>(`${API}/cases/${id}`);
  }

  caseSummary(id: string): Observable<any> {
    return this.http.get<any>(`${API}/cases/${id}/summary`);
  }

  approve(id: string, action: string, totp: string): Observable<any> {
    return this.http.post<any>(
      `${API}/cases/${id}/actions/${action}/approve`,
      {},
      { headers: { 'X-TOTP-Code': totp } },
    );
  }

  exportCase(id: string, format: 'json' | 'csv' | 'pdf'): Observable<Blob> {
    return this.http.get(`${API}/reports/cases/${id}.${format}`, { responseType: 'blob' });
  }

  registerDevice(pushToken: string, platform: string): Observable<any> {
    return this.http.post<any>(`${API}/mobile/devices`, {
      push_token: pushToken,
      platform,
    });
  }

  issueApprovalToken(id: string, action: string): Observable<any> {
    return this.http.post<any>(`${API}/cases/${id}/actions/${action}/approval-token`, {});
  }

  mobileDecision(
    id: string,
    action: string,
    totp: string,
    token: string,
    decision: 'approve' | 'deny',
  ): Observable<any> {
    return this.http.post<any>(
      `${API}/cases/${id}/actions/${action}/approve`,
      { decision },
      {
        headers: {
          'X-TOTP-Code': totp,
          'X-Approval-Channel': 'mobile',
          'X-Approval-Token': token,
        },
      },
    );
  }

  accounts(): Observable<any> {
    return this.http.get<any>(`${API}/accounts`);
  }

  onboardAccount(accountId: string, roleArn: string): Observable<any> {
    return this.http.post<any>(`${API}/accounts`, {
      account_id: accountId,
      role_arn: roleArn,
    });
  }

  updateIngestionHealth(accountId: string, status: string): Observable<any> {
    return this.http.patch<any>(`${API}/accounts/${accountId}/ingestion-health`, { status });
  }

  profile(): Observable<any> {
    return this.http.get<any>(`${API}/profile`);
  }

  changePassword(currentPassword: string, newPassword: string): Observable<any> {
    return this.http.post<any>(`${API}/profile/password`, {
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  users(): Observable<ManagedUser[]> {
    return this.http.get<ManagedUser[]>(`${API}/users`);
  }

  createUser(payload: {
    username: string;
    email?: string | null;
    password: string;
    role: ManagedUser['role'];
    disabled?: boolean;
  }): Observable<ManagedUser> {
    return this.http.post<ManagedUser>(`${API}/users`, payload);
  }

  updateUser(
    username: string,
    payload: Partial<Pick<ManagedUser, 'email' | 'role' | 'disabled'>>,
  ): Observable<ManagedUser> {
    return this.http.patch<ManagedUser>(
      `${API}/users/${encodeURIComponent(username)}`,
      payload,
    );
  }

  deleteUser(username: string): Observable<any> {
    return this.http.delete<any>(`${API}/users/${encodeURIComponent(username)}`);
  }

  resetUserMfa(username: string): Observable<ManagedUser> {
    return this.http.post<ManagedUser>(
      `${API}/users/${encodeURIComponent(username)}/reset-mfa`,
      {},
    );
  }

  resetUserPassword(username: string, newPassword: string): Observable<ManagedUser> {
    return this.http.post<ManagedUser>(
      `${API}/users/${encodeURIComponent(username)}/password-reset`,
      { new_password: newPassword },
    );
  }
}
