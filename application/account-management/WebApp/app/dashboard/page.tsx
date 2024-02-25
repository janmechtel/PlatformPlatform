import { Suspense } from "react";
import { CardSkeleton, MiniCardSkeleton } from "@/ui/dashboard/CardSkeleton";

export default function Page() {
  return (
    <main className="w-full">
      <h1 className="mb-4 text-xl md:text-2xl">
        Dashboard
      </h1>
      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
        <Suspense>
          <div><CardSkeleton /></div>
        </Suspense>
        <Suspense>
          <div><CardSkeleton /></div>
        </Suspense>
        <Suspense>
          <div><CardSkeleton /></div>
        </Suspense>
      </div>
      <div className="mt-6 grid grid-cols-1 gap-6 md:grid-cols-4 lg:grid-cols-8">
        <Suspense>
          <div><MiniCardSkeleton /></div>
        </Suspense>
        <Suspense>
          <div><MiniCardSkeleton /></div>
        </Suspense>
      </div>
    </main>
  );
}
