import type { ReactNode } from "react";
import { useUser } from "./hooks";
import type { UserRole } from "./actions";

export interface SignedInProps {
  children: ReactNode;
  requiredRoles?: UserRole[];
}

/**
 * Show component if user is signed in and has the required role.
 */
export function SignedIn({ children, requiredRoles }: SignedInProps) {
  const user = useUser();
  if (user == null)
    return null;
  if (requiredRoles != null && requiredRoles.includes(user.userRole) === false)
    return null;
  return children;
}
