import { test, expect } from "./fixtures";

test.describe("NHI Registry Page", () => {
  test("NHI registry page loads", async ({ demoPage: page }) => {
    await page.goto("/app/nhi-registry?demo=true");
    await expect(
      page.getByRole("heading", { name: /non-human identities/i }).first(),
    ).toBeVisible();
  });

  test("displays NHI count metrics", async ({ demoPage: page }) => {
    await page.goto("/app/nhi-registry?demo=true");
    await expect(page.getByText("Total NHIs")).toBeVisible();
    await expect(page.getByText("Orphaned")).toBeVisible();
    await expect(page.getByText("Over-Privileged")).toBeVisible();
    await expect(page.getByText("Shadow AI Detected")).toBeVisible();
  });

  test("NHI cards render with risk scores", async ({ demoPage: page }) => {
    await page.goto("/app/nhi-registry?demo=true");
    // Verify NHI cards are rendered
    await expect(page.getByText("svc-prod-deployer")).toBeVisible();

    // Verify risk score gauges are present (the "Risk Score" label appears on each card)
    const riskLabels = page.getByText("Risk Score");
    const count = await riskLabels.count();
    expect(count).toBeGreaterThanOrEqual(5);
  });

  test("type filter works", async ({ demoPage: page }) => {
    await page.goto("/app/nhi-registry?demo=true");

    // Select "AI Agent" from the type filter dropdown
    const typeSelect = page.locator("select").first();
    await typeSelect.selectOption("AI Agent");

    // Should only show AI agent NHIs
    await expect(page.getByText("shieldops-investigation-agent")).toBeVisible();
    await expect(page.getByText("customer-support-bot")).toBeVisible();

    // Service accounts should no longer be visible
    await expect(page.getByText("svc-prod-deployer")).not.toBeVisible();

    // Results count should reflect the filter
    await expect(page.getByText("4 results")).toBeVisible();
  });

  test("search filters by name", async ({ demoPage: page }) => {
    await page.goto("/app/nhi-registry?demo=true");

    // Type in the search box
    const searchInput = page.getByPlaceholder("Search by name...");
    await searchInput.fill("payment");

    // Should filter to only matching NHIs — none match "payment" in the demo data
    // but "legacy-admin-key" doesn't match so it should be hidden
    await expect(page.getByText("svc-prod-deployer")).not.toBeVisible();

    // Clear and search for something that exists
    await searchInput.clear();
    await searchInput.fill("shieldops");
    await expect(page.getByText("shieldops-investigation-agent")).toBeVisible();
    await expect(page.getByText("shieldops-remediation-agent")).toBeVisible();
  });

  test("shadow AI section visible", async ({ demoPage: page }) => {
    await page.goto("/app/nhi-registry?demo=true");

    // Verify the Shadow AI Detections section
    await expect(page.getByText("Shadow AI Detections")).toBeVisible();

    // Verify shadow AI cards with provider names
    await expect(page.getByText("OpenAI")).toBeVisible();
    await expect(page.getByText("Azure OpenAI")).toBeVisible();

    // Verify detection details
    await expect(page.getByText("DNS monitoring")).toBeVisible();
  });

  test("shadow AI has register and block actions", async ({ demoPage: page }) => {
    await page.goto("/app/nhi-registry?demo=true");

    // Verify Register and Block buttons exist on shadow AI cards
    const registerButtons = page.getByText("Register");
    const blockButtons = page.getByText("Block");

    const registerCount = await registerButtons.count();
    const blockCount = await blockButtons.count();

    // There are 3 shadow AI entries, each with Register and Block
    expect(registerCount).toBeGreaterThanOrEqual(3);
    expect(blockCount).toBeGreaterThanOrEqual(3);
  });
});
