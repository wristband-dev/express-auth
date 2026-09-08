import { Response } from 'express';

import type { AuthFailureReason } from '@wristband/typescript-auth';

/**
 * Sends appropriate error response based on failure reason.
 */
export function sendAuthFailureResponse(res: Response, reason: AuthFailureReason): void {
  let status: number;
  let errorMessage: string;

  switch (reason) {
    case 'unexpected_error':
      status = 500;
      errorMessage = 'Internal Server Error';
      break;
    case 'csrf_failed':
      status = 403;
      errorMessage = 'Forbidden';
      break;
    case 'not_authenticated':
    case 'token_refresh_failed':
    default:
      status = 401;
      errorMessage = 'Unauthorized';
  }

  res.status(status).json({ error: errorMessage });
}
