import { Request, Response, NextFunction } from 'express';
import { getSessionSync, Session, SessionData, SessionOptions } from '@wristband/typescript-session';

/**
 * Augments the Express Request interface to include a session property.
 *
 * This type declaration adds the `session` property to all Express Request objects,
 * providing type-safe access to session data and methods throughout your Express application.
 *
 * To add custom fields to your session data, augment the SessionData interface:
 *
 * @example
 * ```typescript
 * declare module '@wristband/typescript-session' {
 *   interface SessionData {
 *     cartId?: string;
 *     theme?: 'light' | 'dark';
 *   }
 * }
 * ```
 */
declare module 'express-serve-static-core' {
  interface Request {
    /** Session instance with management methods and typed data access */
    session: Session<SessionData> & SessionData;
  }
}

/**
 * Executes a callback immediately before response headers are written.
 *
 * Hooks into `res.writeHead()` to run the listener once before headers are sent,
 * then restores the original method. Useful for deferred session flushes or
 * computed header values.
 *
 * @param res - Express Response object
 * @param listener - Function to run before headers are written
 *
 * @internal
 */
function onHeaders(res: Response, listener: () => void): void {
  const prevWriteHead = res.writeHead.bind(res);

  res.writeHead = function (...args: Parameters<typeof res.writeHead>): Response {
    if (!res.headersSent) {
      try {
        listener.call(res);
      } catch (err) {
        // Silent failure - if this throws, the environment is usually fundamentally broken
      }
    }

    // Restore original to prevent repeated hooks
    (res.writeHead as any) = prevWriteHead;
    return prevWriteHead(...args);
  } as any;
}

/**
 * Create Wristband session middleware for Express.
 *
 * @param options - Session configuration options from @wristband/typescript-session
 * @returns Express middleware function
 *
 * @example
 * ```typescript
 * import { createWristbandSession } from '@wristband/express-auth';
 *
 * app.use(createWristbandSession({
 *   secrets: process.env.SESSION_SECRET,
 *   cookieName: 'my-app.session',
 *   maxAge: 3600, // 1 hour
 *   secure: process.env.NODE_ENV === 'production'
 * }));
 * ```
 */
export function createWristbandSession(options: SessionOptions) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.session = getSessionSync(req, res, options);
      req.session.enableDeferredMode();

      onHeaders(res, () => {
        if (!res.headersSent) {
          try {
            req.session.flushSync();
          } catch (err) {
            // Silent failure - if this throws, the environment is usually fundamentally broken
          }
        }
      });

      next();
    } catch (error) {
      next(error);
    }
  };
}
