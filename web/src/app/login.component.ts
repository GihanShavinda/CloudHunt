import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from './auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="login-page">
      <div class="login-card panel-accent">
        <div class="login-logo">CH</div>
        <div class="eyebrow">CLOUD SECURITY OPERATIONS</div>
        <h2>Welcome to CloudHunt</h2>
        <p class="intro">Investigate AWS identity attacks, privilege-escalation paths, cloud detections and human-approved containment.</p>

        <div class="form-group">
          <label>Username</label>
          <input [(ngModel)]="username" placeholder="Username" autocomplete="username" (keyup.enter)="submit()" />
        </div>
        <div class="form-group">
          <label>Password</label>
          <input [(ngModel)]="password" type="password" placeholder="Password" autocomplete="current-password" (keyup.enter)="submit()" />
        </div>

        <button class="full-button" (click)="submit()" [disabled]="loading">
          {{ loading ? 'Authenticating…' : 'Secure Sign In' }}
        </button>
        <p class="bad form-error" *ngIf="error">{{ error }}</p>

        <div class="auth-switch">
          <span>New to CloudHunt?</span>
          <a routerLink="/signup">Create a Viewer account</a>
        </div>

        <div class="login-features">
          <span>RBAC</span><span>TOTP MFA</span><span>ATT&CK Cloud</span><span>Human-in-the-loop</span>
        </div>
      </div>
    </div>
  `,
})
export class LoginComponent {
  username = 'analyst';
  password = '';
  error = '';
  loading = false;

  constructor(private auth: AuthService, private router: Router) {}

  submit(): void {
    this.error = '';
    if (!this.username.trim() || !this.password) {
      this.error = 'Username and password are required.';
      return;
    }
    this.loading = true;
    this.auth.login(this.username.trim(), this.password).subscribe({
      next: () => {
        this.loading = false;
        this.router.navigateByUrl('/dashboard');
      },
      error: (err) => {
        this.loading = false;
        this.error = err?.status === 401
          ? 'Invalid username or password.'
          : 'Login failed. Check the CloudHunt API connection.';
      },
    });
  }
}
