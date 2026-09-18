import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, map, of } from 'rxjs';
import { AuthService } from './auth.service';

export const adminGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (!auth.isAuthed) {
    return router.createUrlTree(['/login']);
  }

  if (auth.user) {
    return auth.isAdmin
      ? true
      : router.createUrlTree(['/dashboard']);
  }

  return auth.loadCurrentUser().pipe(
    map(() => auth.isAdmin
      ? true
      : router.createUrlTree(['/dashboard'])),
    catchError(() => of(router.createUrlTree(['/login']))),
  );
};
