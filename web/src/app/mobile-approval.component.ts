import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ApiService } from './api.service';
import { AuthService } from './auth.service';

@Component({
  selector: 'app-mobile-approval',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="mobile-approval-shell">
      <div class="mobile-header"><div><div class="eyebrow">HUMAN APPROVAL</div><h1>Mobile Decision</h1></div><a [routerLink]="['/case', caseId]">Open full case →</a></div>
      <div class="panel summary-panel" *ngIf="summary"><div class="section-title-row"><h2>Case Summary</h2><span class="badge" [class.badge-danger]="summary.rejected" [class.badge-success]="!summary.rejected">{{ summary.source === 'template' ? 'template summary' : 'AI summary' }}</span></div><span class="badge badge-danger" *ngIf="summary.rejected">AI summary rejected</span><p>{{ summary.summary }}</p></div>
      <div class="panel"><div class="eyebrow">DEVICE</div><h2>Push Registration</h2><div class="form-group"><label>Push token</label><input [(ngModel)]="pushToken" placeholder="Device push token" /></div><div class="form-group"><label>Platform</label><select [(ngModel)]="platform"><option>android</option><option>ios</option><option>web</option></select></div><button (click)="registerDevice()">Register device</button><p class="ok" *ngIf="deviceId">Registered: {{ deviceId }}</p></div>
      <div class="panel" *ngIf="detail"><div class="eyebrow">PENDING ACTIONS</div><h2>Human Approval Queue</h2><div *ngFor="let a of pendingActions()" class="approval-card"><div class="section-title-row"><strong>{{ a.action_key }}</strong><span class="badge badge-warning">HUMAN</span></div><div class="muted small" *ngFor="let r of a.reasons">• {{ r }}</div><ng-container *ngIf="auth.canApprove; else noPerm"><input [(ngModel)]="totp[a.action_key]" placeholder="TOTP code" maxlength="8" /><div class="toolbar"><button (click)="decide(a.action_key, 'approve')">Approve</button><button class="danger-button" (click)="decide(a.action_key, 'deny')">Deny</button></div></ng-container><ng-template #noPerm><span class="badge badge-warning">Analyst/Admin role required</span></ng-template></div><div class="empty-state compact-empty" *ngIf="!pendingActions().length"><span>✓</span><strong>No pending human approvals</strong></div></div>
      <p class="bad" *ngIf="error">{{ error }}</p>
    </div>
  `,
})
export class MobileApprovalComponent implements OnInit {
  caseId = ''; detail: any; summary: any; totp: Record<string, string> = {}; pushToken = ''; platform = 'web'; deviceId = ''; error = '';
  constructor(private route: ActivatedRoute, private api: ApiService, public auth: AuthService) {}
  ngOnInit(): void { this.caseId = this.route.snapshot.paramMap.get('id') || ''; this.load(); }
  load(): void { this.api.caseDetail(this.caseId).subscribe((d) => (this.detail = d)); this.api.caseSummary(this.caseId).subscribe((s) => (this.summary = s)); }
  pendingActions(): any[] { return (this.detail?.recommended_actions || []).filter((a: any) => a.status === 'pending' && a.mode === 'human'); }
  registerDevice(): void { this.error = ''; this.api.registerDevice(this.pushToken, this.platform).subscribe({ next: (d) => (this.deviceId = d.device_id), error: (e) => (this.error = e?.error?.detail || 'Device registration failed.') }); }
  decide(actionKey: string, decision: 'approve' | 'deny'): void { this.error = ''; this.api.issueApprovalToken(this.caseId, actionKey).subscribe({ next: (issued) => this.api.mobileDecision(this.caseId, actionKey, this.totp[actionKey] || '', issued.token, decision).subscribe({ next: () => this.load(), error: (e) => (this.error = e?.error?.detail || 'Mobile approval failed.') }), error: (e) => (this.error = e?.error?.detail || 'Could not create approval token.') }); }
}
