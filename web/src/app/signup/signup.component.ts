import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-signup',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="login-page signup-page">
      <div class="login-card signup-card panel-accent">
        <div class="login-logo">CH</div>
        <div class="eyebrow">CREATE CLOUDHUNT ACCOUNT</div>
        <h2>Join CloudHunt</h2>
        <p class="intro">
          Self-service accounts are created with <strong>Viewer</strong> access.
          An Administrator can promote your role later.
        </p>

        <div class="form-group">
          <label>Username</label>
          <input
            [(ngModel)]="username"
            placeholder="e.g. gihan.r"
            autocomplete="username"
          />
          <small class="field-hint">3-64 characters: letters, numbers, dot, underscore or hyphen.</small>
        </div>

        <div class="form-group">
          <label>Email</label>
          <input
            [(ngModel)]="email"
            type="email"
            placeholder="you@example.com"
            autocomplete="email"
          />
        </div>

        <div class="form-group">
          <label>Password</label>
          <input
            [(ngModel)]="password"
            type="password"
            placeholder="Minimum 12 characters"
            autocomplete="new-password"
          />
        </div>

        <div class="form-group">
          <label>Confirm Password</label>
          <input
            [(ngModel)]="confirmPassword"
            type="password"
            placeholder="Repeat password"
            autocomplete="new-password"
            (keyup.enter)="submit()"
          />
        </div>

        <div class="signup-role-notice">
          <span class="badge badge-info">Viewer</span>
          <div>
            <strong>Least-privilege signup</strong>
            <small>Public registration cannot create Analyst or Administrator accounts.</small>
          </div>
        </div>

        <button class="full-button" (click)="submit()" [disabled]="loading">
          {{ loading ? 'Creating account…' : 'Create Account' }}
        </button>

        <div class="alert danger-alert" *ngIf="error">{{ error }}</div>
        <div class="alert success-alert" *ngIf="success">{{ success }}</div>

        <div class="auth-switch">
          <span>Already registered?</span>
          <a routerLink="/login">Sign in</a>
        </div>
      </div>
    </div>
  `,
})
export class SignupComponent {
  username = '';
  email = '';
  password = '';
  confirmPassword = '';
  loading = false;
  error = '';
  success = '';

  constructor(private auth: AuthService, private router: Router) {}

  submit(): void {
    this.error = '';
    this.success = '';

    const username = this.username.trim();
    const email = this.email.trim();

    if (!username || !email || !this.password || !this.confirmPassword) {
      this.error = 'All fields are required.';
      return;
    }

    if (this.password.length < 12) {
      this.error = 'Password must be at least 12 characters.';
      return;
    }

    if (this.password !== this.confirmPassword) {
      this.error = 'Passwords do not match.';
      return;
    }

    this.loading = true;
    this.auth.signup({ username, email, password: this.password }).subscribe({
      next: () => {
        this.loading = false;
        this.success = 'Account created successfully with Viewer access. Redirecting to sign in…';
        setTimeout(() => this.router.navigateByUrl('/login'), 900);
      },
      error: (err) => {
        this.loading = false;
        this.error = err?.error?.detail || 'Unable to create account.';
      },
    });
  }
}
