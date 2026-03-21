import { Link } from "react-router-dom";
import { Home, ArrowLeft } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-6 p-8 text-center">
      <div className="text-8xl font-bold tracking-tight text-gray-800/80">404</div>
      <h1 className="text-2xl font-bold tracking-tight text-gray-50">Page not found</h1>
      <p className="max-w-md text-sm text-gray-500">
        The page you're looking for doesn't exist or has been moved.
      </p>
      <div className="flex gap-3">
        <button
          onClick={() => window.history.back()}
          className="btn-secondary"
        >
          <ArrowLeft className="h-4 w-4" />
          Go Back
        </button>
        <Link
          to="/app"
          className="btn-primary"
        >
          <Home className="h-4 w-4" />
          Dashboard
        </Link>
      </div>
    </div>
  );
}
