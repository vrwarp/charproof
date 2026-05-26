import { getAuth } from "../config";
import type { AuthProvider } from "../core/interfaces";

export class FirebaseAuthProvider implements AuthProvider {
  getCurrentUser() {
    const user = getAuth().currentUser;
    if (!user) return null;
    return {
      uid: user.uid,
      isAnonymous: user.isAnonymous,
      email: user.email || undefined,
      displayName: user.displayName || undefined
    };
  }
}
