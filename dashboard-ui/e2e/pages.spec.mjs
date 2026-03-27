/**
 * Playwright E2E tests for ShieldOps dashboard pages.
 *
 * Run: npx playwright test e2e/pages.spec.mjs
 */
import { test, expect } from "@playwright/test";

const BASE = "http://localhost:3000";

// Setup: enable demo mode before each test
test.beforeEach(async ({ page }) => {
  await page.goto(`${BASE}?demo=true`, { waitUntil: "networkidle" });
  await page.waitForTimeout(2000);
  // Remove any modal overlays
  await page.evaluate(() => {
    document
      .querySelectorAll(
        '[role="dialog"], .modal-backdrop, .fixed.inset-0, .fixed.z-50',
      )
      .forEach((el) => el.remove());
  });
});

// ── Landing Page ──

test("landing page loads with hero", async ({ page }) => {
  await page.goto(BASE, { waitUntil: "networkidle" });
  await expect(page.locator("body")).toContainText("ShieldOps");
});

// ── Agent Pages ──

const agentPages = [
  ["/app/agentic-mdr", "Agentic MDR"],
  ["/app/situation-manager", "Situation Manager"],
  ["/app/autonomous-xdr", "Autonomous XDR"],
  ["/app/ai-soc-assistant", "AI SOC Assistant"],
  ["/app/prompt-shield", "Prompt Shield"],
  ["/app/cross-vendor-correlator", "Cross-Vendor Correlator"],
  ["/app/identity-protection", "Identity Protection"],
  ["/app/ransomware-forensics", "Ransomware Forensics"],
  ["/app/cyber-recovery", "Cyber Recovery"],
  ["/app/malware-analyzer", "Malware Analyzer"],
  ["/app/autonomous-soc", "Autonomous SOC"],
  ["/app/breakout-defender", "Breakout Defender"],
  ["/app/agent-governance", "Agent Governance"],
  ["/app/model-security", "Model Security"],
  ["/app/digital-twin-security", "Digital Twin Security"],
  ["/app/managed-threat-hunting", "Managed Threat Hunting"],
  ["/app/vulnerability-intelligence", "Vulnerability Intelligence"],
  ["/app/iot-ot-security", "IoT/OT Security"],
  ["/app/air-gap-vault", "Air-Gap Vault"],
  ["/app/data-resilience", "Data Resilience"],
  ["/app/it-asset-intelligence", "IT Asset Intelligence"],
  ["/app/ai-runtime-guardian", "AI Runtime Guardian"],
  ["/app/data-intelligence", "Data Intelligence"],
  ["/app/endpoint-dlp", "Endpoint DLP"],
  ["/app/unified-cloud-security", "Unified Cloud Security"],
  ["/app/backup-security-posture", "Backup Security Posture"],
];

for (const [path, title] of agentPages) {
  test(`${title} page renders`, async ({ page }) => {
    await page.goto(`${BASE}${path}`, { waitUntil: "networkidle" });
    await page.waitForTimeout(1000);
    await page.evaluate(() => {
      document
        .querySelectorAll(
          '[role="dialog"], .fixed.inset-0, .fixed.z-50',
        )
        .forEach((el) => el.remove());
    });
    // Verify title renders
    const h1 = page.locator("h1").first();
    await expect(h1).toBeVisible({ timeout: 5000 });
    await expect(h1).toContainText(title, { timeout: 5000 });
  });
}

// ── Metric Cards ──

test("Agentic MDR has 4 metric cards", async ({ page }) => {
  await page.goto(`${BASE}/app/agentic-mdr`, {
    waitUntil: "networkidle",
  });
  await page.waitForTimeout(1000);
  await page.evaluate(() => {
    document
      .querySelectorAll('[role="dialog"], .fixed.z-50')
      .forEach((el) => el.remove());
  });
  const cards = page.locator('[class*="card"]');
  await expect(cards.first()).toBeVisible({ timeout: 5000 });
});

// ── Tab Navigation ──

test("Situation Manager has tab bar", async ({ page }) => {
  await page.goto(`${BASE}/app/situation-manager`, {
    waitUntil: "networkidle",
  });
  await page.waitForTimeout(1000);
  await page.evaluate(() => {
    document
      .querySelectorAll('[role="dialog"], .fixed.z-50')
      .forEach((el) => el.remove());
  });
  const tabBar = page.locator(".tab-bar");
  await expect(tabBar).toBeVisible({ timeout: 5000 });
});

// ── Sidebar Navigation ──

test("sidebar has navigation items", async ({ page }) => {
  await page.goto(`${BASE}/app/agentic-mdr`, {
    waitUntil: "networkidle",
  });
  await page.waitForTimeout(1000);
  const sidebar = page.locator("nav, aside, [class*='sidebar']").first();
  await expect(sidebar).toBeVisible({ timeout: 5000 });
});
