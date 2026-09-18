import { Routes } from '@angular/router';
import { LoginComponent } from './login.component';
import { DashboardComponent } from './dashboard/dashboard.component';
import { CaseComponent } from './case/case.component';
import { CasesComponent } from './cases/cases.component';
import { IamGraphComponent } from './iam-graph/iam-graph.component';
import { DetectionsComponent } from './detections/detections.component';
import { AccountsComponent } from './accounts/accounts.component';
import { ProfileComponent } from './profile/profile.component';
import { MobileApprovalComponent } from './mobile-approval.component';
import { SignupComponent } from './signup/signup.component';
import { UsersComponent } from './users/users.component';
import { authGuard } from './auth.guard';
import { adminGuard } from './admin.guard';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
  { path: 'login', component: LoginComponent },
  { path: 'signup', component: SignupComponent },
  { path: 'dashboard', component: DashboardComponent, canActivate: [authGuard] },
  { path: 'cases', component: CasesComponent, canActivate: [authGuard] },
  { path: 'iam-graph', component: IamGraphComponent, canActivate: [authGuard] },
  { path: 'detections', component: DetectionsComponent, canActivate: [authGuard] },
  { path: 'accounts', component: AccountsComponent, canActivate: [authGuard] },
  { path: 'users', component: UsersComponent, canActivate: [adminGuard] },
  { path: 'profile', component: ProfileComponent, canActivate: [authGuard] },
  { path: 'case/:id', component: CaseComponent, canActivate: [authGuard] },
  { path: 'mobile/case/:id', component: MobileApprovalComponent, canActivate: [authGuard] },
  { path: '**', redirectTo: 'dashboard' },
];
