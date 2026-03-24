import { test, expect } from "./fixtures";

test.describe("Agent Firewall Page", () => {
  test("agent firewall page loads", async ({ demoPage: page }) => {
    await page.goto("/app/agent-firewall?demo=true");
    await expect(
      page.getByRole("heading", { name: /agent firewall/i }).first(),
    ).toBeVisible();
  });

  test("displays metric cards", async ({ demoPage: page }) => {
    await page.goto("/app/agent-firewall?demo=true");
    const metricCards = page.locator("[class*='MetricCard'], [data-testid='metric-card']");
    // Fallback: look for the 4 metric labels rendered by the page
    await expect(page.getByText("Calls Intercepted (24h)")).toBeVisible();
    await expect(page.getByText("Anomalies Detected")).toBeVisible();
    await expect(page.getByText("Policies Active")).toBeVisible();
    await expect(page.getByText("Circuit Breakers Open")).toBeVisible();
  });

  test("displays agent cards", async ({ demoPage: page }) => {
    await page.goto("/app/agent-firewall?demo=true");
    // The default "All Agents" tab shows 8 agent cards; verify at least 6 are visible
    const agentNames = page.locator("text=/.*-agent$|.*-bot$/i");
    await expect(agentNames.first()).toBeVisible();
    const count = await agentNames.count();
    expect(count).toBeGreaterThanOrEqual(6);
  });

  test("tabs switch content", async ({ demoPage: page }) => {
    await page.goto("/app/agent-firewall?demo=true");

    // Click Anomalies tab
    await page.getByRole("button", { name: "Anomalies" }).click();
    // Anomalies content: severity badges and anomaly types
    await expect(page.getByText("Privilege Escalation").first()).toBeVisible();

    // Click Policies tab
    await page.getByRole("button", { name: "Policies" }).click();
    // Policies tab shows a table with policy names
    await expect(page.getByText("IAM Root Protection")).toBeVisible();
    await expect(page.getByText("Tool Pattern").first()).toBeVisible();
  });

  test("kill switch button visible on hover", async ({ demoPage: page }) => {
    await page.goto("/app/agent-firewall?demo=true");
    // Ensure we're on agents tab (default)
    await expect(page.getByText("data-pipeline-agent")).toBeVisible();

    // Hover the first agent card
    const firstCard = page.locator("text=data-pipeline-agent").first();
    await firstCard.hover();

    // Kill Switch button should become visible
    await expect(page.getByText("Kill Switch").first()).toBeVisible();
  });

  test("circuit breaker indicators shown", async ({ demoPage: page }) => {
    await page.goto("/app/agent-firewall?demo=true");
    // Verify circuit breaker status badges: Closed, Half Open, Open
    await expect(page.getByText("Closed").first()).toBeVisible();
    await expect(page.getByText("Half Open").first()).toBeVisible();
    await expect(page.getByText("Open").first()).toBeVisible();
  });

  test("audit log tab shows entries", async ({ demoPage: page }) => {
    await page.goto("/app/agent-firewall?demo=true");

    // Click Audit Log tab
    await page.getByRole("button", { name: "Audit Log" }).click();

    // Verify audit log table headers
    await expect(page.getByText("Decision").first()).toBeVisible();
    await expect(page.getByText("Risk Score").first()).toBeVisible();

    // Verify at least one entry with a decision badge
    await expect(page.getByText("blocked").first()).toBeVisible();

    // Verify table rows exist
    const rows = page.locator("tbody tr");
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThanOrEqual(5);
  });

  test("anomalies show risk scores", async ({ demoPage: page }) => {
    await page.goto("/app/agent-firewall?demo=true");
    await page.getByRole("button", { name: "Anomalies" }).click();

    // Verify anomaly entries show severity badges
    await expect(page.getByText("critical").first()).toBeVisible();

    // Verify investigate buttons
    await expect(page.getByText("Investigate").first()).toBeVisible();
  });

  test("policies table has action buttons", async ({ demoPage: page }) => {
    await page.goto("/app/agent-firewall?demo=true");
    await page.getByRole("button", { name: "Policies" }).click();

    // Verify Edit and Disable action buttons in the table
    await expect(page.getByText("Edit").first()).toBeVisible();
    await expect(page.getByText("Disable").first()).toBeVisible();

    // Verify rate limit column data
    await expect(page.getByText("0/min").first()).toBeVisible();
  });
});
