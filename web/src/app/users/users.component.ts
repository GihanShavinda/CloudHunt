import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, ManagedUser } from '../api.service';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-users',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="page-heading">
      <div>
        <div class="eyebrow">USER ADMINISTRATION</div>
        <h1>User Management</h1>
        <p>Manage CloudHunt platform accounts, RBAC roles, account state and MFA.</p>
      </div>

      <div class="heading-actions">
        <span class="badge badge-success">{{ activeCount }} active</span>
        <button (click)="showCreate = !showCreate">+ Add User</button>
      </div>
    </div>

    <div class="user-stats-grid">
      <div class="panel mini-stat">
        <small>Total Users</small>
        <strong>{{ users.length }}</strong>
        <span class="muted small">Registered accounts</span>
      </div>
      <div class="panel mini-stat">
        <small>Administrators</small>
        <strong>{{ countRole('administrator') }}</strong>
        <span class="muted small">Platform management</span>
      </div>
      <div class="panel mini-stat">
        <small>Cloud Analysts</small>
        <strong>{{ countRole('cloud_analyst') }}</strong>
        <span class="muted small">Investigation & response</span>
      </div>
      <div class="panel mini-stat">
        <small>Viewers</small>
        <strong>{{ countRole('viewer') }}</strong>
        <span class="muted small">Read-only access</span>
      </div>
    </div>

    <section class="panel panel-accent user-create-panel" *ngIf="showCreate">
      <div class="section-title-row">
        <div>
          <div class="eyebrow">ADMINISTRATOR ACTION</div>
          <h2>Create User</h2>
        </div>
        <button class="secondary compact" (click)="resetCreateForm()">Close</button>
      </div>

      <div class="user-form-grid">
        <div class="form-group">
          <label>Username</label>
          <input [(ngModel)]="newUser.username" placeholder="username" />
        </div>
        <div class="form-group">
          <label>Email</label>
          <input [(ngModel)]="newUser.email" type="email" placeholder="user@example.com" />
        </div>
        <div class="form-group">
          <label>Temporary Password</label>
          <input [(ngModel)]="newUser.password" type="password" placeholder="Minimum 12 characters" />
        </div>
        <div class="form-group">
          <label>Role</label>
          <select [(ngModel)]="newUser.role">
            <option value="viewer">Viewer</option>
            <option value="cloud_analyst">Cloud Analyst</option>
            <option value="administrator">Administrator</option>
          </select>
        </div>
      </div>

      <div class="toolbar">
        <button (click)="createUser()" [disabled]="saving">
          {{ saving ? 'Creating…' : 'Create User' }}
        </button>
        <button class="secondary" (click)="resetCreateForm()">Cancel</button>
      </div>
    </section>

    <div class="alert success-alert" *ngIf="message">{{ message }}</div>
    <div class="alert danger-alert" *ngIf="error">{{ error }}</div>

    <section class="panel">
      <div class="filter-bar user-filter-bar">
        <div class="search-field">
          <span>⌕</span>
          <input [(ngModel)]="query" placeholder="Search username or email…" />
        </div>
        <select [(ngModel)]="roleFilter">
          <option value="all">All roles</option>
          <option value="administrator">Administrators</option>
          <option value="cloud_analyst">Cloud Analysts</option>
          <option value="viewer">Viewers</option>
        </select>
      </div>

      <div class="table-wrap">
        <table class="user-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>MFA</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let user of filteredUsers">
              <td>
                <div class="user-cell">
                  <div class="user-avatar">{{ initials(user.username) }}</div>
                  <div>
                    <strong>{{ user.username }}</strong>
                    <small *ngIf="user.username === auth.user?.username">Current account</small>
                  </div>
                </div>
              </td>

              <td>
                <input
                  class="table-input"
                  [(ngModel)]="user.email"
                  [placeholder]="'No email set'"
                />
              </td>

              <td>
                <select class="table-select" [(ngModel)]="user.role">
                  <option value="administrator">Administrator</option>
                  <option value="cloud_analyst">Cloud Analyst</option>
                  <option value="viewer">Viewer</option>
                </select>
              </td>

              <td>
                <select
                  class="table-select"
                  [ngModel]="user.disabled ? 'disabled' : 'active'"
                  (ngModelChange)="user.disabled = $event === 'disabled'"
                  [disabled]="user.username === auth.user?.username"
                >
                  <option value="active">Active</option>
                  <option value="disabled">Disabled</option>
                </select>
              </td>

              <td>
                <span class="badge" [ngClass]="user.mfa_enabled ? 'badge-success' : 'badge-warning'">
                  {{ user.mfa_enabled ? 'Enabled' : 'Not set' }}
                </span>
              </td>

              <td class="row-action">
                <div class="user-actions">
                  <button class="secondary compact" (click)="saveUser(user)">Save</button>
                  <button class="secondary compact" (click)="resetMfa(user)">Reset MFA</button>
                  <button class="secondary compact" (click)="resetPassword(user)">Password</button>
                  <button
                    class="danger-button compact"
                    (click)="deleteUser(user)"
                    [disabled]="user.username === auth.user?.username"
                  >
                    Delete
                  </button>
                </div>
              </td>
            </tr>

            <tr *ngIf="!filteredUsers.length">
              <td colspan="6">
                <div class="empty-state compact-empty">
                  <span>◎</span>
                  <strong>No users match the current filters.</strong>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  `,
})
export class UsersComponent implements OnInit {
  users: ManagedUser[] = [];
  query = '';
  roleFilter = 'all';
  showCreate = false;
  saving = false;
  error = '';
  message = '';

  newUser: {
    username: string;
    email: string;
    password: string;
    role: ManagedUser['role'];
  } = {
    username: '',
    email: '',
    password: '',
    role: 'viewer',
  };

  constructor(public auth: AuthService, private api: ApiService) {}

  ngOnInit(): void {
    this.load();
  }

  get activeCount(): number {
    return this.users.filter((user) => !user.disabled).length;
  }

  get filteredUsers(): ManagedUser[] {
    const q = this.query.trim().toLowerCase();
    return this.users.filter((user) => {
      const roleOk = this.roleFilter === 'all' || user.role === this.roleFilter;
      const queryOk = !q || `${user.username} ${user.email || ''}`.toLowerCase().includes(q);
      return roleOk && queryOk;
    });
  }

  countRole(role: ManagedUser['role']): number {
    return this.users.filter((user) => user.role === role).length;
  }

  initials(username: string): string {
    return username.slice(0, 2).toUpperCase();
  }

  load(): void {
    this.error = '';
    this.api.users().subscribe({
      next: (users) => (this.users = users),
      error: (err) => (this.error = err?.error?.detail || 'Unable to load users.'),
    });
  }

  createUser(): void {
    this.error = '';
    this.message = '';

    if (!this.newUser.username.trim() || !this.newUser.password) {
      this.error = 'Username and temporary password are required.';
      return;
    }
    if (this.newUser.password.length < 12) {
      this.error = 'Temporary password must be at least 12 characters.';
      return;
    }

    this.saving = true;
    this.api.createUser({
      username: this.newUser.username.trim(),
      email: this.newUser.email.trim() || null,
      password: this.newUser.password,
      role: this.newUser.role,
    }).subscribe({
      next: (user) => {
        this.saving = false;
        this.message = `User '${user.username}' created.`;
        this.resetCreateForm();
        this.load();
      },
      error: (err) => {
        this.saving = false;
        this.error = err?.error?.detail || 'Unable to create user.';
      },
    });
  }

  saveUser(user: ManagedUser): void {
    this.clearMessages();
    this.api.updateUser(user.username, {
      email: user.email || null,
      role: user.role,
      disabled: user.disabled,
    }).subscribe({
      next: (updated) => {
        Object.assign(user, updated);
        this.message = `User '${user.username}' updated.`;
        if (user.username === this.auth.user?.username) {
          this.auth.loadCurrentUser().subscribe();
        }
      },
      error: (err) => {
        this.error = err?.error?.detail || 'Unable to update user.';
        this.load();
      },
    });
  }

  resetMfa(user: ManagedUser): void {
    this.clearMessages();
    if (!confirm(`Reset MFA for ${user.username}? They will need to configure TOTP again.`)) {
      return;
    }
    this.api.resetUserMfa(user.username).subscribe({
      next: (updated) => {
        Object.assign(user, updated);
        this.message = `MFA reset for '${user.username}'.`;
      },
      error: (err) => (this.error = err?.error?.detail || 'Unable to reset MFA.'),
    });
  }

  resetPassword(user: ManagedUser): void {
    this.clearMessages();
    const newPassword = prompt(`Enter a new temporary password for ${user.username} (minimum 12 characters):`);
    if (newPassword === null) return;
    if (newPassword.length < 12) {
      this.error = 'Temporary password must be at least 12 characters.';
      return;
    }
    this.api.resetUserPassword(user.username, newPassword).subscribe({
      next: () => (this.message = `Password reset for '${user.username}'.`),
      error: (err) => (this.error = err?.error?.detail || 'Unable to reset password.'),
    });
  }

  deleteUser(user: ManagedUser): void {
    this.clearMessages();
    if (user.username === this.auth.user?.username) {
      this.error = 'You cannot delete your own account.';
      return;
    }
    if (!confirm(`Delete CloudHunt user '${user.username}'? Disabling the account is preferred when possible.`)) {
      return;
    }
    this.api.deleteUser(user.username).subscribe({
      next: () => {
        this.message = `User '${user.username}' deleted.`;
        this.load();
      },
      error: (err) => (this.error = err?.error?.detail || 'Unable to delete user.'),
    });
  }

  resetCreateForm(): void {
    this.showCreate = false;
    this.newUser = {
      username: '',
      email: '',
      password: '',
      role: 'viewer',
    };
  }

  private clearMessages(): void {
    this.error = '';
    this.message = '';
  }
}
