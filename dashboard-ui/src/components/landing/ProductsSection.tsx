import { Link } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import clsx from "clsx";
import { PRODUCTS } from "../../config/products";

const products = Object.values(PRODUCTS);

export default function ProductsSection() {
  return (
    <section className="px-6 py-24">
      <div className="mx-auto max-w-5xl">
        <div className="mb-4">
          <p className="text-sm font-medium uppercase tracking-wider text-brand-400">
            Platform
          </p>
        </div>
        <div className="mb-12 max-w-2xl">
          <h2 className="text-3xl font-bold tracking-tight text-gray-50">
            Six products, one platform
          </h2>
          <p className="mt-4 text-lg leading-relaxed text-gray-400">
            Deploy the modules you need today. Add more as your operations
            mature. Everything shares the same agent infrastructure, data layer,
            and policy engine.
          </p>
        </div>

        <div className="grid gap-px overflow-hidden rounded-xl border border-gray-800 bg-gray-800 sm:grid-cols-2 lg:grid-cols-3">
          {products.map((product) => {
            const Icon = product.icon;
            return (
              <Link
                key={product.id}
                to={`/products/${product.id}`}
                className="group flex flex-col bg-gray-950 p-6 transition-colors hover:bg-gray-900"
              >
                <div className="flex items-center gap-3">
                  <Icon className={clsx("h-5 w-5 shrink-0", product.color)} />
                  <h3 className="font-semibold text-gray-100">{product.name}</h3>
                </div>
                <p className="mt-1 text-xs text-gray-500">{product.tagline}</p>
                <p className="mt-3 flex-1 text-sm leading-relaxed text-gray-400">
                  {product.description}
                </p>
                <span className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-brand-400 transition-colors group-hover:text-brand-300">
                  Explore
                  <ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
                </span>
              </Link>
            );
          })}
        </div>
      </div>
    </section>
  );
}
