import { describe, expect, it } from "vitest";
import { APP_TITLE } from "./App";

describe("App placeholder", () => {
  it("exports the application title", () => {
    expect(APP_TITLE).toBe("Strongroom Vault");
  });
});
