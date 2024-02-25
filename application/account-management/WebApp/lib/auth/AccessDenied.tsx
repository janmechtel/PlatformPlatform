import type { ReactNode } from "react";
import { useUser } from "./hooks";
import type { UserRole } from "./actions";

export interface AccessDeniedProps {
  children: ReactNode;
  requiredRoles: UserRole[];
}

/**
 * Display component if user is logged in but does not have the required role.
 */
export function AccessDenied({ children, requiredRoles }: AccessDeniedProps) {
  const user = useUser();
  if (user == null)
    return null;
  if (requiredRoles.includes(user.userRole))
    return null;
  return children;
}
