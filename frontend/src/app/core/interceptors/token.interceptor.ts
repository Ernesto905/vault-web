import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError, ReplaySubject } from 'rxjs';
import { AuthService } from '../../services/auth.service';

let refreshTokenSubject = new ReplaySubject<string>(1);
let isRefreshing = false;

export const tokenInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);

  // Explicit Authorization Header
  if (req.headers.has('Authorization')) {
    return next(req).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401) {
          // If the refresh token request itself fails, we must logout.
          if (req.url.includes('/refresh')) {
            authService.logout();
          }
          // Otherwise, just pass the 401 through.
        }
        return throwError(() => error);
      }),
    );
  }

  // Attach the token automatically if not present and not an auth endpoint.
  if (
    !req.url.includes('/login') &&
    !req.url.includes('/register') &&
    !req.url.includes('/refresh')
  ) {
    const token = authService.getToken();
    if (token) {
      req = req.clone({
        setHeaders: { Authorization: `Bearer ${token}` },
      });
    }
  }

  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status !== 401) {
        return throwError(() => error);
      }

      // If the refresh endpoint returns 401, the refresh token is invalid/expired.
      if (req.url.includes('/refresh')) {
        authService.logout();
        return throwError(() => error);
      }

      // Handle 401 by attempting to refresh the token
      if (isRefreshing) {
        return refreshTokenSubject.pipe(
          switchMap((token) => {
            const retryReq = req.clone({
              setHeaders: { Authorization: `Bearer ${token}` },
            });
            return next(retryReq);
          }),
        );
      }

      isRefreshing = true;
      refreshTokenSubject = new ReplaySubject<string>(1);

      return authService.refresh().pipe(
        switchMap((res) => {
          isRefreshing = false;
          authService.saveToken(res.token);
          refreshTokenSubject.next(res.token);
          refreshTokenSubject.complete();

          const retryReq = req.clone({
            setHeaders: { Authorization: `Bearer ${res.token}` },
          });

          return next(retryReq);
        }),
        catchError((refreshErr) => {
          isRefreshing = false;
          refreshTokenSubject.error(refreshErr);
          authService.logout();
          return throwError(() => refreshErr);
        }),
      );
    }),
  );
};
