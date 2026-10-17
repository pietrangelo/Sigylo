// The signed-in account of this tab, in memory only: nothing is written to
// storage, so closing or reloading the tab signs out.

import { forget, type Session } from './account';

export const signedIn: { session: Session | null } = $state({ session: null });

/** The live session, or null once the relay would have ended it anyway. */
export function currentSession(): Session | null {
  const session = signedIn.session;
  if (session !== null && session.expiresAt * 1000 <= Date.now()) {
    forget(session);
    signedIn.session = null;
  }
  return signedIn.session;
}
