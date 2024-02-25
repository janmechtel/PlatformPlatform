import { createContext, useCallback, useRef, useState } from "react";
import { authenticate, getUserInfo, initialUserInfo, logout } from "./actions";
import type { State, UserInfo } from "./actions";

export interface AuthenticationContextType {
  user: UserInfo | null;
  reloadUserInfo: () => void;
  signInAction: (_: State, formData: FormData) => Promise<State>;
  signOutAction: () => Promise<State>;
}

export const AuthenticationContext = createContext<AuthenticationContextType>({
  user: initialUserInfo,
  reloadUserInfo: () => {},
  signInAction: async () => ({}),
  signOutAction: async () => ({}),
});

export interface AuthenticationProviderProps {
  children: React.ReactNode;
  navigate?: (path: string) => void;
  afterSignOut?: string;
  afterSignIn?: string;
};

/**
 * Provide authentication context to the application.
 */
export function AuthenticationProvider({ children, navigate, afterSignIn, afterSignOut }: AuthenticationProviderProps) {
  const [user, setUser] = useState<UserInfo | null>(initialUserInfo);
  const fetching = useRef(false);

  const reloadUserInfo = useCallback(async () => {
    if (fetching.current)
      return;
    fetching.current = true;
    try {
      const newUserInfo = await getUserInfo();
      setUser(newUserInfo);
    }
    catch (error) {
      setUser(null);
    }
    fetching.current = false;
  }, [setUser]);

  const signOutAction = useCallback(async () => {
    const result = await logout();
    setUser(null);
    if (navigate && afterSignOut)
      navigate(afterSignOut);
    return result;
  }, [setUser, navigate, afterSignOut]);

  const signInAction = useCallback(async (state: State, formData: FormData) => {
    const result = await authenticate(state, formData);
    if (result.success)
      setUser(await getUserInfo());

    if (result.success && navigate && afterSignIn)
      navigate(afterSignIn);
    return result;
  }, [navigate, afterSignIn]);

  return (
    <AuthenticationContext.Provider value={{ user, reloadUserInfo, signInAction, signOutAction }}>
      {children}
    </AuthenticationContext.Provider>
  );
};
