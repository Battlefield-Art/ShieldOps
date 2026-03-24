import { test, expect } from "./fixtures";

test.describe("MCP Security Page", () => {
  test("MCP security page loads", async ({ demoPage: page }) => {
    await page.goto("/app/mcp-security?demo=true");
    await expect(
      page.getByRole("heading", { name: /mcp security/i }).first(),
    ).toBeVisible();
  });

  test("displays server metrics", async ({ demoPage: page }) => {
    await page.goto("/app/mcp-security?demo=true");
    await expect(page.getByText("MCP Servers")).toBeVisible();
    await expect(page.getByText("God Key Risks")).toBeVisible();
    await expect(page.getByText("Supply Chain Vulns")).toBeVisible();
    await expect(page.getByText("Zero-Trust Compliance")).toBeVisible();
  });

  test("servers tab shows table", async ({ demoPage: page }) => {
    await page.goto("/app/mcp-security?demo=true");

    // Servers tab is default — verify table headers
    await expect(page.getByText("Server").first()).toBeVisible();
    await expect(page.getByText("Transport").first()).toBeVisible();
    await expect(page.getByText("Auth").first()).toBeVisible();
    await expect(page.getByText("Trust").first()).toBeVisible();

    // Verify server rows
    await expect(page.getByText("postgres-mcp")).toBeVisible();
    await expect(page.getByText("github-mcp")).toBeVisible();

    // Verify table has multiple rows
    const rows = page.locator("tbody tr");
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThanOrEqual(10);
  });

  test("god keys tab shows alerts", async ({ demoPage: page }) => {
    await page.goto("/app/mcp-security?demo=true");

    // Click God Keys tab
    await page.getByRole("button", { name: "God Keys" }).click();

    // Verify god key alert cards
    await expect(page.getByText("vault-mcp").first()).toBeVisible();
    await expect(page.getByText("google-drive-mcp").first()).toBeVisible();
    await expect(page.getByText("internal-tools-mcp").first()).toBeVisible();

    // Verify risk scores are shown
    await expect(page.getByText("Risk: 91")).toBeVisible();
    await expect(page.getByText("Risk: 85")).toBeVisible();

    // Verify blast radius information
    await expect(page.getByText("920 resources")).toBeVisible();

    // Verify recommended actions
    await expect(page.getByText("Credential Scope").first()).toBeVisible();
    await expect(page.getByText("Recommended Action").first()).toBeVisible();

    // Verify action buttons
    await expect(page.getByText("Scope Down")).toBeVisible();
    await expect(page.getByText("Add Auth")).toBeVisible();
    await expect(page.getByText("Split Server")).toBeVisible();
  });

  test("supply chain tab shows vulnerabilities", async ({ demoPage: page }) => {
    await page.goto("/app/mcp-security?demo=true");

    // Click Supply Chain tab
    await page.getByRole("button", { name: "Supply Chain" }).click();

    // Verify table headers
    await expect(page.getByText("Component").first()).toBeVisible();
    await expect(page.getByText("CVEs").first()).toBeVisible();
    await expect(page.getByText("Severity").first()).toBeVisible();

    // Verify CVE entries are shown
    await expect(page.getByText("CVE-2026-1234")).toBeVisible();
    await expect(page.getByText("CVE-2026-5678")).toBeVisible();

    // Verify component names
    await expect(page.getByText("@modelcontextprotocol/sdk")).toBeVisible();
    await expect(page.getByText("mcp-server-postgres")).toBeVisible();

    // Verify severity badges
    await expect(page.getByText("critical").first()).toBeVisible();
    await expect(page.getByText("high").first()).toBeVisible();

    // Verify fix availability indicators
    const rows = page.locator("tbody tr");
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThanOrEqual(5);
  });

  test("zero trust tab shows compliance", async ({ demoPage: page }) => {
    await page.goto("/app/mcp-security?demo=true");

    // Click Zero Trust tab
    await page.getByRole("button", { name: "Zero Trust" }).click();

    // Verify table headers (checklist columns)
    await expect(page.getByText("OAuth2").first()).toBeVisible();
    await expect(page.getByText("TLS").first()).toBeVisible();
    await expect(page.getByText("Cert Valid").first()).toBeVisible();
    await expect(page.getByText("Audit Log").first()).toBeVisible();
    await expect(page.getByText("Scoped Perms").first()).toBeVisible();
    await expect(page.getByText("Compliance").first()).toBeVisible();

    // Verify server names in the checklist
    await expect(page.getByText("postgres-mcp").first()).toBeVisible();
    await expect(page.getByText("github-mcp").first()).toBeVisible();

    // Verify compliance status badges
    await expect(page.getByText("compliant").first()).toBeVisible();
    await expect(page.getByText("non_compliant").first()).toBeVisible();

    // Verify all 12 servers shown
    const rows = page.locator("tbody tr");
    const rowCount = await rows.count();
    expect(rowCount).toBe(12);
  });
});
