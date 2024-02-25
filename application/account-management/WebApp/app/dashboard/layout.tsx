import { SignedIn } from "@/lib/auth/SignedIn";
import { SignedOut } from "@/lib/auth/SignedOut";
import { useSignOutAction, useUser } from "@/lib/auth/hooks";
import { Link } from "@/lib/router/router";
import { Button } from "@/ui/components/Button";

interface LayoutProps { children: React.ReactNode, }

export default function Layout({ children }: Readonly<LayoutProps>) {
  return (
    <>

      <SignedIn>
        <div className="flex h-screen flex-col md:flex-row md:overflow-hidden">
          <div className="w-full flex-none md:w-64">
            <SideNav />
          </div>
          <div className="flex-grow p-6 md:overflow-y-auto md:p-12">{children}</div>
        </div>
      </SignedIn>
      <SignedOut>
        <div className="flex flex-col text-center h-full justify-center">
          You need to be signed in to view this page.
          <Link to="/login" className="font-semibold">SignIn</Link>.
        </div>
      </SignedOut>
    </>
  );
}

function SideNav() {
  const user = useUser();
  const logoutAction = useSignOutAction();

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="font-semibold">User: {user?.userName}</div>
      <Button onPress={logoutAction}>Sign Out</Button>
    </div>
  );
}
