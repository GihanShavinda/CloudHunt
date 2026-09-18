# CloudHunt Signup + User Management Update

This package contains only newly added or updated files.

## What is added

- Public `/signup` page
- Public `POST /auth/signup`
  - always creates the `viewer` role
  - public users cannot choose Administrator or Cloud Analyst
- Administrator-only `/users` page
- Administrator user-management API:
  - list users
  - create users
  - change role
  - enable/disable account
  - reset MFA
  - reset password
  - delete users
- Protection against:
  - non-admin user management
  - deleting your own administrator account
  - disabling the final active administrator
  - demoting the final active administrator
- User Management sidebar item shown only to administrators
- Backend tests for signup/RBAC/user management

## Install

Extract this ZIP into the CloudHunt project root:

`F:\My_Projects\Cloudhunt\cloudhunt`

Allow the folders to merge and replace the included files.

## Run backend tests

```powershell
pytest tests\test_user_management.py -v
pytest -v
```

## Start backend

```powershell
uvicorn cloudhunt.api.main:app --reload --host 0.0.0.0 --port 8000
```

## Build frontend

```powershell
cd web
npm test
npm run build
npm start
```

## Test signup

Open:

`http://localhost:4200/signup`

New public accounts are created as `viewer`.

## Test User Management

Login with the development administrator:

- Username: `admin`
- Password: `ChangeMe!Admin1`

Then open:

`http://localhost:4200/users`

Change the development password before using this outside the lab.
