import type { RouteLocation, RouterHistory } from "@openclaw/uirouter";
import { describe, expect, it, vi } from "vitest";
import { startApplicationRouter, type ApplicationRouter } from "./app-routes.ts";
import type { ApplicationContext } from "./app/context.ts";

describe("initial dynamic route restoration", () => {
  it.each([
    { pathname: "/settings/general", search: "", hash: "" },
    { pathname: "/chat/main", search: "?panel=details", hash: "" },
    { pathname: "/chat/main", search: "", hash: "#operator-choice" },
  ])(
    "does not replay startup over newer navigation: $pathname | $search | $hash",
    async (target) => {
      let finishStart!: () => void;
      const started = new Promise<void>((resolve) => {
        finishStart = resolve;
      });
      let currentLocation: RouteLocation = { pathname: "/chat/main", search: "", hash: "" };
      const navigate = vi.fn().mockResolvedValue(undefined);
      const router = { start: vi.fn(() => started), navigate } as unknown as ApplicationRouter;
      const history = {
        location: () => currentLocation,
        push: vi.fn(),
        replace: vi.fn(),
        listen: vi.fn(() => () => undefined),
      } satisfies RouterHistory;
      const pending = startApplicationRouter(router, history, "", {} as ApplicationContext);
      currentLocation = target;
      finishStart();
      await pending;
      expect(navigate).not.toHaveBeenCalled();
      expect(currentLocation).toEqual(target);
    },
  );

  it("restores the original dynamic session path when startup still owns it", async () => {
    const location = { pathname: "/chat/main", search: "?panel=details", hash: "#message" };
    const navigate = vi.fn().mockResolvedValue(undefined);
    const router = {
      start: vi.fn().mockResolvedValue(undefined),
      navigate,
    } as unknown as ApplicationRouter;
    const history = {
      location: () => location,
      push: vi.fn(),
      replace: vi.fn(),
      listen: vi.fn(() => () => undefined),
    } satisfies RouterHistory;
    const context = {} as ApplicationContext;
    await startApplicationRouter(router, history, "", context);
    expect(navigate).toHaveBeenCalledExactlyOnceWith(
      "chat",
      context,
      { history: "none", revalidate: true },
      location,
    );
  });
});
