// Control UI tests retain operator navigation while cold startup completes.
import { chromium, type Browser, type Locator } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  canRunPlaywrightChromium,
  controlUiSessionUrl,
  installMockGateway,
  resolvePlaywrightChromiumExecutablePath,
  startControlUiE2eServer,
  type ControlUiE2eServer,
} from "../test-helpers/control-ui-e2e.ts";

const chromiumExecutablePath = resolvePlaywrightChromiumExecutablePath(chromium.executablePath());
const chromiumAvailable = canRunPlaywrightChromium(chromiumExecutablePath);
const allowMissingChromium = process.env.OPENCLAW_UI_E2E_ALLOW_MISSING_CHROMIUM === "1";
const describeControlUiE2e = chromiumAvailable || !allowMissingChromium ? describe : describe.skip;
let browser: Browser;
let server: ControlUiE2eServer;

async function trimmedTextContents(locator: Locator): Promise<string[]> {
  return (await locator.allTextContents()).map((text) => text.trim());
}

describeControlUiE2e("Control UI router startup mocked Gateway E2E", () => {
  beforeAll(async () => {
    if (!chromiumAvailable) {
      throw new Error(`Playwright Chromium is unavailable at ${chromiumExecutablePath}`);
    }
    server = await startControlUiE2eServer();
    browser = await chromium.launch({ executablePath: chromiumExecutablePath });
  });

  afterAll(async () => {
    await browser?.close();
    await server?.close();
  });

  it("keeps settings navigation while the initial chat module finishes loading", async () => {
    const context = await browser.newContext({
      locale: "en-US",
      serviceWorkers: "block",
      viewport: { height: 900, width: 1440 },
    });
    const page = await context.newPage();
    let releaseChat!: () => void;
    const chatBlocked = new Promise<void>((resolve) => {
      releaseChat = resolve;
    });
    let chatRequested = false;
    await page.route(/\/pages\/chat\/chat-page\.ts(?:\?|$)/u, async (route) => {
      chatRequested = true;
      await chatBlocked;
      await route.continue().catch(() => undefined);
    });
    await installMockGateway(page);

    try {
      await page.goto(controlUiSessionUrl(server.baseUrl, "agent:main:main"));
      await expect.poll(() => chatRequested).toBe(true);
      const sidebar = page.locator("openclaw-app-sidebar");
      await sidebar.locator(".sidebar-identity-card").click();
      await sidebar
        .locator("wa-dropdown.sidebar-identity-menu")
        .getByRole("menuitem", { exact: true, name: "Settings" })
        .click();
      await expect.poll(() => new URL(page.url()).pathname).toBe("/settings/general");
      const settingsSidebar = page.locator(".settings-sidebar");
      await expect.poll(() => settingsSidebar.isVisible()).toBe(true);

      releaseChat();
      await page.waitForFunction(() => Boolean(customElements.get("openclaw-chat-page")));
      // Let the released module's import continuations and Lit render commit;
      // a stale startup replay must not take ownership back from Settings.
      await page.evaluate(
        () =>
          new Promise<void>((resolve) => {
            requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
          }),
      );
      await expect.poll(() => new URL(page.url()).pathname).toBe("/settings/general");
      const settingsSearch = settingsSidebar.getByRole("searchbox", { name: "Search settings" });
      await settingsSearch.fill("theme");
      await expect
        .poll(() => trimmedTextContents(settingsSidebar.locator(".settings-sidebar__item")))
        .toEqual(["Appearance"]);
    } finally {
      releaseChat();
      await context.close();
    }
  });
});
