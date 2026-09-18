import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import {
  Observable,
  switchMap,
  tap,
} from 'rxjs';

export const API =
  'http://127.0.0.1:8000';


export interface Me {
  username: string;
  role: string;
  email?: string | null;
  mfa_enabled?: boolean;
  disabled?: boolean;
}


export interface SignupPayload {
  username: string;
  email: string;
  password: string;
}


interface LoginResponse {
  access_token: string;
  token_type?: string;
}


@Injectable({
  providedIn: 'root',
})
export class AuthService {

  token: string | null =
    localStorage.getItem(
      'cloudhunt_token',
    );

  user: Me | null = null;


  constructor(
    private http: HttpClient,
  ) {}


  // =========================================================
  // LOGIN
  // =========================================================

  login(
    username: string,
    password: string,
  ): Observable<Me> {

    const body =
      new URLSearchParams();

    body.set(
      'username',
      username,
    );

    body.set(
      'password',
      password,
    );

    return this.http
      .post<LoginResponse>(
        `${API}/auth/login`,
        body.toString(),
        {
          headers: {
            'Content-Type':
              'application/x-www-form-urlencoded',
          },
        },
      )
      .pipe(

        tap(
          (response) => {

            this.token =
              response.access_token;

            localStorage.setItem(
              'cloudhunt_token',
              response.access_token,
            );
          },
        ),

        switchMap(
          () =>
            this.loadCurrentUser(),
        ),
      );
  }


  // =========================================================
  // PUBLIC SIGNUP
  // =========================================================
  //
  // IMPORTANT:
  //
  // /auth/signup = PUBLIC
  // /auth/register = ADMIN-ONLY legacy endpoint
  //
  // Self-service users are always created as Viewer.
  // =========================================================

  signup(
    payload: SignupPayload,
  ): Observable<Me> {

    return this.http.post<Me>(
      `${API}/auth/signup`,
      payload,
    );
  }


  // Optional alias if another component
  // calls register().
  register(
    payload: SignupPayload,
  ): Observable<Me> {

    return this.signup(
      payload,
    );
  }


  // =========================================================
  // CURRENT USER
  // =========================================================

  loadCurrentUser():
    Observable<Me> {

    return this.http
      .get<Me>(
        `${API}/auth/me`,
      )
      .pipe(

        tap(
          (me) => {

            this.user = me;

          },
        ),
      );
  }


  // =========================================================
  // LOGOUT
  // =========================================================

  logout(): void {

    this.token = null;

    this.user = null;

    localStorage.removeItem(
      'cloudhunt_token',
    );
  }


  // =========================================================
  // AUTH STATE
  // =========================================================

  get isAuthed(): boolean {

    return !!this.token;
  }


  get role(): string | null {

    return (
      this.user?.role ??
      null
    );
  }


  // =========================================================
  // RBAC
  // =========================================================

  get isAdmin(): boolean {

    return (
      this.role ===
      'administrator'
    );
  }


  get isAnalyst(): boolean {

    return (
      this.role ===
      'cloud_analyst'
    );
  }


  get isViewer(): boolean {

    return (
      this.role ===
      'viewer'
    );
  }


  get canApprove(): boolean {

    return (
      this.isAdmin ||
      this.isAnalyst
    );
  }


  get canManageUsers():
    boolean {

    return this.isAdmin;
  }


  get canManageAccounts():
    boolean {

    return this.isAdmin;
  }
}