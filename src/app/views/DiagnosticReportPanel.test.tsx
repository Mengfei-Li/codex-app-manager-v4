import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { managerApi } from "../../services/managerApi";
import { I18nProvider } from "../i18n";
import { DiagnosticReportPanel } from "./DiagnosticReportPanel";

vi.mock("../../services/managerApi", () => ({
  managerApi: {
    getLatestDiagnosticReport: vi.fn(),
    retryLatestDiagnosticUpload: vi.fn(),
    deleteLatestDiagnosticBundle: vi.fn(),
  },
}));

const report = {
  schemaVersion: 1,
  reportId: "IR-20260803-ABCDEF01",
  operationId: "op-1",
  localBundlePath: "C:/diagnostics/report.zip",
  bundleSha256: "a".repeat(64),
  uploadStatus: "pending",
  uploadAttempts: 0,
  serverReceiptId: null,
  supportSummary: "download failed",
  updatedAtUnix: 1,
};

function view() {
  return render(
    <I18nProvider>
      <DiagnosticReportPanel active />
    </I18nProvider>,
  );
}

beforeEach(() => {
  localStorage.setItem("cam.lang", "en");
  vi.mocked(managerApi.getLatestDiagnosticReport).mockResolvedValue(report);
  vi.mocked(managerApi.retryLatestDiagnosticUpload).mockResolvedValue({
    ...report,
    uploadStatus: "uploaded",
    serverReceiptId: "receipt-1",
  });
  vi.mocked(managerApi.deleteLatestDiagnosticBundle).mockResolvedValue({
    ...report,
    localBundlePath: "",
    uploadStatus: "deleted",
  });
  vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
});

describe("DiagnosticReportPanel", () => {
  it("shows the durable report and retries a pending upload", async () => {
    view();
    expect(await screen.findByText(/IR-20260803-ABCDEF01/)).toBeInTheDocument();
    expect(screen.getByText("C:/diagnostics/report.zip")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(managerApi.retryLatestDiagnosticUpload).toHaveBeenCalledOnce());
    expect(await screen.findByText(/uploaded/)).toBeInTheDocument();
    expect(screen.getByText(/receipt-1/)).toBeInTheDocument();
  });

  it("copies support-safe report metadata", async () => {
    view();
    await screen.findByText(/IR-20260803-ABCDEF01/);
    await userEvent.click(screen.getByRole("button", { name: "Copy diagnostics" }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      expect.stringContaining("IR-20260803-ABCDEF01"),
    );
  });
});
