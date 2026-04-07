import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import Pricing from "../Pricing";

// Mock framer-motion
vi.mock("framer-motion", () => ({
  motion: {
    div: ({
      children,
      ...props
    }: React.PropsWithChildren<Record<string, unknown>>) => (
      <div {...props}>{children}</div>
    ),
  },
  useInView: () => true,
  AnimatePresence: ({ children }: React.PropsWithChildren) => <>{children}</>,
}));

function renderPricing() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Pricing />
      </BrowserRouter>
    </QueryClientProvider>,
  );
}

describe("Pricing", () => {
  it("renders pricing header", () => {
    renderPricing();
    expect(screen.getByText("Simple, usage-based pricing")).toBeInTheDocument();
  });

  it("renders Most Popular badge on highlighted tier", () => {
    renderPricing();
    expect(screen.getAllByText("Most Popular").length).toBeGreaterThanOrEqual(1);
  });

  it("renders FAQ section", () => {
    renderPricing();
    // FAQ heading exists in some form
    expect(document.body.textContent).toMatch(/FAQ|frequently/i);
  });
});
