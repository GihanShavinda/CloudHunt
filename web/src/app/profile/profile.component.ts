import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../api.service';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="page-heading"><div><div class="eyebrow">IDENTITY & ACCESS</div><h1>Profile & Security</h1><p>Your CloudHunt platform identity, RBAC role and password controls.</p></div></div>
    <div class="two-column-layout">
      <section class="panel profile-card">
        <div class="profile-avatar">{{ initials() }}</div>
        <h2>{{ profile?.username || auth.user?.username }}</h2>
        <span class="badge badge-purple">{{ profile?.role || auth.user?.role }}</span>
        <div class="detail-list profile-details"><div><span>Authentication</span><strong>JWT bearer</strong></div><div><span>Approval MFA</span><strong class="ok">TOTP required</strong></div><div><span>Approval capability</span><strong>{{ auth.canApprove ? 'Enabled' : 'Read only' }}</strong></div></div>
      </section>
      <section class="panel">
        <div class="eyebrow">CREDENTIAL SECURITY</div><h2>Change Password</h2><p class="muted">Use at least 12 characters. Approval actions continue to require TOTP MFA.</p>
        <div class="form-group"><label>Current password</label><input [(ngModel)]="currentPassword" type="password" autocomplete="current-password" /></div>
        <div class="form-group"><label>New password</label><input [(ngModel)]="newPassword" type="password" autocomplete="new-password" /></div>
        <button (click)="changePassword()">Update password</button>
        <p class="ok" *ngIf="message">{{ message }}</p><p class="bad" *ngIf="error">{{ error }}</p>
      </section>
    </div>
  `,
})
export class ProfileComponent implements OnInit {
  profile: any;
  currentPassword = '';
  newPassword = '';
  message = '';
  error = '';

  constructor(private api: ApiService, public auth: AuthService) {}

  ngOnInit(): void { this.api.profile().subscribe((p) => (this.profile = p)); }

  initials(): string {
    const u = this.profile?.username || this.auth.user?.username || 'CH';
    return u.slice(0, 2).toUpperCase();
  }

  changePassword(): void {
    this.message = ''; this.error = '';
    if (this.newPassword.length < 12) { this.error = 'New password must be at least 12 characters.'; return; }
    this.api.changePassword(this.currentPassword, this.newPassword).subscribe({
      next: () => { this.message = 'Password updated successfully.'; this.currentPassword = ''; this.newPassword = ''; },
      error: (e) => (this.error = e?.error?.detail || 'Password update failed.'),
    });
  }
}
