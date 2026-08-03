import { useCallback, useEffect, useState } from "react";

import type { LatestDiagnosticReport, OperationDiagnosticState } from "../../shared/types";
import { managerApi } from "../../services/managerApi";
import { useI18n } from "../i18n";

export function DiagnosticReportPanel({
  active,
  initial,
}: {
  active: boolean;
  initial?: OperationDiagnosticState | null;
}) {
  const { t } = useI18n();
  const [report, setReport] = useState<LatestDiagnosticReport | null>(null);
  const [busy, setBusy] = useState<"copy" | "retry" | "delete" | null>(null);
  const [message, setMessage] = useState("");

  const refresh = useCallback(() => {
    const request = managerApi.getLatestDiagnosticReport?.();
    if (!request) return;
    void request.then(setReport).catch(() => setMessage(t("diagnostics.loadFailed")));
  }, [t]);

  useEffect(() => {
    if (active || initial) refresh();
  }, [active, initial, refresh]);

  const reportId = report?.reportId ?? initial?.reportId;
  const localPath = report?.localBundlePath ?? initial?.localBundlePath ?? "";
  const uploadStatus = report?.uploadStatus ?? initial?.uploadStatus ?? "";
  if (!reportId) return null;

  const copy = async () => {
    setBusy("copy");
    try {
      await navigator.clipboard.writeText(
        [
          t("diagnostics.report", { id: reportId }),
          t("diagnostics.uploadState", { state: uploadStatus }),
          localPath ? `${t("diagnostics.localPath")}: ${localPath}` : "",
          report?.serverReceiptId
            ? t("diagnostics.receiptValue", { id: report.serverReceiptId })
            : "",
        ]
          .filter(Boolean)
          .join("\n"),
      );
      setMessage(t("diagnostics.copied"));
    } catch {
      setMessage(t("diagnostics.copyFailed"));
    } finally {
      setBusy(null);
    }
  };

  const retry = async () => {
    setBusy("retry");
    setMessage("");
    try {
      setReport(await managerApi.retryLatestDiagnosticUpload());
      setMessage(t("diagnostics.retryDone"));
    } catch {
      setMessage(t("diagnostics.retryFailed"));
    } finally {
      setBusy(null);
    }
  };

  const remove = async () => {
    if (!window.confirm(t("diagnostics.deleteConfirm"))) return;
    setBusy("delete");
    setMessage("");
    try {
      setReport(await managerApi.deleteLatestDiagnosticBundle());
      setMessage(t("diagnostics.deleted"));
    } catch {
      setMessage(t("diagnostics.deleteFailed"));
    } finally {
      setBusy(null);
    }
  };

  const deleted = uploadStatus === "deleted";
  return (
    <section className="diagnostic-report-panel" aria-label={t("diagnostics.title")}>
      <strong>{t("diagnostics.report", { id: reportId })}</strong>
      <div>{t("diagnostics.uploadState", { state: uploadStatus })}</div>
      {localPath && !deleted ? <code>{localPath}</code> : null}
      {report?.serverReceiptId ? (
        <div>{t("diagnostics.receiptValue", { id: report.serverReceiptId })}</div>
      ) : null}
      <div className="diagnostic-report-actions">
        <button className="btn ghost" onClick={copy} disabled={busy !== null}>
          {busy === "copy" ? t("uninstall.working") : t("crash.copy")}
        </button>
        {!deleted && uploadStatus !== "uploaded" ? (
          <button className="btn ghost" onClick={retry} disabled={busy !== null}>
            {busy === "retry" ? t("uninstall.working") : t("settings.retry")}
          </button>
        ) : null}
        {!deleted ? (
          <button className="btn danger" onClick={remove} disabled={busy !== null}>
            {busy === "delete" ? t("uninstall.working") : t("diagnostics.delete")}
          </button>
        ) : null}
      </div>
      {message ? <div className="diagnostic-report-message" role="status">{message}</div> : null}
    </section>
  );
}
