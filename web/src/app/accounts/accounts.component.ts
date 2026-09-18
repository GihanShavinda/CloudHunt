import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../api.service';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-accounts',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="page-heading">
      <div><div class="eyebrow">PLATFORM</div><h1>AWS Accounts</h1><p>Single-account onboarding and ingestion-health tracking for the CloudHunt MVP.</p></div>
      <span class="badge badge-info">{{ accounts.length }} onboarded</span>
    </div>

    <div class="two-column-layout">
      <section class="panel">
        <div class="section-title-row"><div><div class="eyebrow">CONNECTED SOURCES</div><h2>Account Inventory</h2></div><button class="secondary compact" (click)="load()">Refresh</button></div>
        <div *ngFor="let a of accounts" class="account-row">
          <div class="account-icon">AWS</div>
          <div class="account-main"><strong>{{ a.account_id }}</strong><div class="muted small mono">{{ a.role_arn }}</div><div class="tag-line"><span class="badge" [class.badge-success]="a.ingestion_health === 'healthy'" [class.badge-warning]="a.ingestion_health === 'pending'" [class.badge-danger]="a.ingestion_health === 'degraded'">{{ a.ingestion_health }}</span><span class="muted small">{{ a.last_event_at || 'No event timestamp yet' }}</span></div></div>
          <select *ngIf="auth.canApprove" [(ngModel)]="a._status" (change)="setHealth(a)"><option value="">Set health…</option><option value="healthy">healthy</option><option value="degraded">degraded</option><option value="pending">pending</option></select>
        </div>
        <div class="empty-state" *ngIf="!accounts.length"><span>⬢</span><strong>No AWS account onboarded</strong><p>Administrators can register the lab/sandbox account using a least-privilege cross-account role.</p></div>
      </section>

      <section class="panel" *ngIf="auth.isAdmin; else adminOnly">
        <div class="eyebrow">ADMINISTRATION</div><h2>Onboard AWS Account</h2><p class="muted">Register an account ID and the read-mostly CloudHunt cross-account role ARN.</p>
        <div class="form-group"><label>AWS Account ID</label><input [(ngModel)]="accountId" placeholder="111122223333" /></div>
        <div class="form-group"><label>Cross-account Role ARN</label><input [(ngModel)]="roleArn" placeholder="arn:aws:iam::111122223333:role/CloudHuntReadRole" /></div>
        <button (click)="onboard()">Onboard account</button>
        <p class="ok" *ngIf="message">{{ message }}</p><p class="bad" *ngIf="error">{{ error }}</p>
      </section>
      <ng-template #adminOnly><section class="panel"><div class="empty-state"><span>🔒</span><strong>Administrator permission required</strong><p>You can view account health, but only administrators can onboard new AWS accounts.</p></div></section></ng-template>
    </div>
  `,
})
export class AccountsComponent implements OnInit {
  accounts: any[] = [];
  accountId = '';
  roleArn = '';
  message = '';
  error = '';

  constructor(private api: ApiService, public auth: AuthService) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.api.accounts().subscribe({ next: (r) => (this.accounts = r.accounts || []), error: (e) => (this.error = e?.error?.detail || 'Could not load accounts.') });
  }

  onboard(): void {
    this.message = ''; this.error = '';
    this.api.onboardAccount(this.accountId.trim(), this.roleArn.trim()).subscribe({
      next: () => { this.message = 'AWS account onboarded.'; this.accountId = ''; this.roleArn = ''; this.load(); },
      error: (e) => (this.error = e?.error?.detail || 'Account onboarding failed.'),
    });
  }

  setHealth(account: any): void {
    if (!account._status) return;
    this.api.updateIngestionHealth(account.account_id, account._status).subscribe({ next: () => this.load(), error: (e) => (this.error = e?.error?.detail || 'Health update failed.') });
  }
}
