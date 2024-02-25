import heroDesktop from "./hero-desktop.png";
import heroMobile from "./hero-mobile.png";
import { SignUpForm } from "@/ui/Auth/SignUpForm";

export default function SignUpPage() {
  return (
    <main className="flex min-h-screen flex-col">
      <div className="flex grow flex-col gap-4 md:flex-row">

        <div className="flex flex-col items-center justify-center gap-6 md:w-2/5 p-6">
          <SignUpForm />
        </div>
        <div className="flex items-center justify-center p-6 bg-gray-50 md:w-3/5 md:px-28 md:py-12">
          {/* Add Hero Images Here */}
          <img
            src={heroMobile}
            width={560}
            height={620}
            className="block md:hidden"
            alt="Screenshots of the dashboard project showing mobile versions"
          />
          <img
            src={heroDesktop}
            width={1000}
            height={760}
            className="hidden md:block"
            alt="Screenshots of the dashboard project showing desktop and mobile versions"
          />
        </div>
      </div>
    </main>
  );
}
