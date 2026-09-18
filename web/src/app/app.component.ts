import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from './auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <div class="app-shell" *ngIf="auth.isAuthed; else publicLayout">
      <aside class="sidebar">
        <div class="sidebar-brand">
          <div class="brand-icon">CH</div>
          <div class="brand-copy">
            <div class="brand-name">Cloud<span>Hunt</span></div>
            <div class="brand-subtitle">Cloud Defense Platform</div>
          </div>
        </div>

        <div class="sidebar-section-label">Operations</div>
        <nav class="sidebar-nav">
          <a routerLink="/dashboard" routerLinkActive="active" class="nav-link">
            <span class="nav-icon">▦</span><span class="nav-label">Dashboard</span>
          </a>
          <a routerLink="/cases" routerLinkActive="active" class="nav-link">
            <span class="nav-icon">◇</span><span class="nav-label">Cases</span>
          </a>
          <a routerLink="/detections" routerLinkActive="active" class="nav-link">
            <span class="nav-icon">⌁</span><span class="nav-label">Detections</span>
          </a>
          <a routerLink="/iam-graph" routerLinkActive="active" class="nav-link">
            <span class="nav-icon">◎</span><span class="nav-label">IAM Graph</span>
          </a>
        </nav>

        <div class="sidebar-section-label">Platform</div>
        <nav class="sidebar-nav">
          <a routerLink="/accounts" routerLinkActive="active" class="nav-link">
            <span class="nav-icon">⬢</span><span class="nav-label">AWS Accounts</span>
          </a>
          <a routerLink="/profile" routerLinkActive="active" class="nav-link">
            <span class="nav-icon">◉</span><span class="nav-label">Profile & Security</span>
          </a>
        </nav>

        <ng-container *ngIf="auth.isAdmin">
          <div class="sidebar-section-label">Administration</div>
          <nav class="sidebar-nav">
            <a routerLink="/users" routerLinkActive="active" class="nav-link">
              <span class="nav-icon">♙</span><span class="nav-label">User Management</span>
            </a>
          </nav>
        </ng-container>

        <div class="sidebar-bottom">
          <div class="system-status">
            <span class="status-dot"></span>
            <div>
              <strong>CloudHunt online</strong>
              <small>Detection pipeline ready</small>
            </div>
          </div>
        </div>
      </aside>

      <div class="workspace">
        <header class="topbar">
          <div>
            <div class="topbar-title">Cloud Security Operations Center</div>
            <div class="muted small">Identity attack paths · Detection · Response</div>
          </div>
          <div class="topbar-right">
            <span class="badge badge-success">● LIVE</span>
            <span class="badge badge-info" *ngIf="auth.user">{{ auth.user.username }}</span>
            <span class="badge badge-purple" *ngIf="auth.user">{{ auth.user.role }}</span>
            <button class="secondary compact" (click)="logout()">Sign out</button>
          </div>
        </header>

        <main class="workspace-content"><router-outlet></router-outlet></main>
      </div>
    </div>

    <ng-template #publicLayout>
      <header class="public-header">
        <a routerLink="/login" class="public-brand">Cloud<span>Hunt</span></a>
        <span style="flex:1"></span>
        <a routerLink="/login" class="public-nav-link">Sign in</a>
        <a routerLink="/signup" class="button-link compact">Create account</a>
      </header>
      <router-outlet></router-outlet>
    </ng-template>
  `,
})
export class AppComponent implements OnInit {
  constructor(public auth: AuthService, private router: Router) {}

  ngOnInit(): void {
    if (this.auth.token && !this.auth.user) {
      this.auth.loadCurrentUser().subscribe({
        error: () => {
          this.auth.logout();
          this.router.navigateByUrl('/login');
        },
      });
    }
  }

  logout(): void {
    this.auth.logout();
    this.router.navigateByUrl('/login');
  }
}
