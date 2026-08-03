import { useEffect, type RefObject } from "react";

import type { DownloadProgress, OperationSnapshot } from "../../shared/types";
import type { FailureSurface } from "../errorCopy";
import { Icon } from "../icons";
import { useI18n, type TKey } from "../i18n";
import { FailureBanner, Ring, TopBar } from "../components";
import { mib } from "../format";
import { acquireNavLock } from "../navLock";
import { DiagnosticReportPanel } from "./DiagnosticReportPanel";

export type DownloadStopIntent = "pause" | "cancel";

export interface PausedDownload {
  kind: "perform" | "install";
  dl: DownloadProgress | null;
}

function duration(seconds: number): string {
  const bounded = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(bounded / 60);
  const remainder = bounded % 60;
  return minutes > 0 ? `${minutes}m ${remainder}s` : `${remainder}s`;
}

const ACTION_KEYS: Record<string, TKey> = {
  preflight: "progress.action.preflight",
  "download-payload": "progress.action.download-payload",
  "verify-signature-and-hash": "progress.action.verify-signature-and-hash",
  "apply-platform-package": "progress.action.apply-platform-package",
  "commit-installation": "progress.action.commit-installation",
  "verify-and-clean-up": "progress.action.verify-and-clean-up",
};

/** The full-screen download/install progress view, shared by the Mac and
 *  Windows homes (byte-for-byte identical before this extraction). Owns the
 *  progressbar accessibility semantics so assistive tech can follow a
 *  destructive install/update: `role="progressbar"` + aria-value*, and an
 *  aria-live phase line ("preparing" → "downloading" → "finishing"). */
export function ProgressScreen({
  scene,
  scopeRef,
  paused,
  dl,
  dlPct,
  dlBytes,
  dlSpeed,
  operation,
  installing,
  downloadStop,
  downloadStopBusy,
  failure,
  onResume,
  onPause,
  onCancel,
}: {
  scene: string;
  scopeRef: RefObject<HTMLDivElement | null>;
  paused: PausedDownload | null;
  /** Live progress (null when not transferring). */
  dl: DownloadProgress | null;
  /** Eased display figures (useCountUp), so the readouts glide. */
  dlPct: number;
  dlBytes: number;
  dlSpeed: number;
  /** Durable backend snapshot; survives renderer reload and is the UI authority. */
  operation: OperationSnapshot | null;
  /** Whether the operation is a fresh install (vs an in-place update). */
  installing: boolean;
  downloadStop: DownloadStopIntent | null;
  downloadStopBusy: boolean;
  failure: FailureSurface | null;
  onResume: () => void;
  onPause: () => void;
  onCancel: () => void;
}) {
  const { t } = useI18n();

  // This screen is the operation's isolation chamber: while it is mounted,
  // navigation elsewhere (the expanded rail) must not offer an exit that could
  // start a concurrent operation or unmount the progress listeners.
  useEffect(() => acquireNavLock(), []);

  // Paused reads from its captured snapshot; live runs from the eased `dl`.
  const snap = paused ? paused.dl : dl;
  const ui = operation?.ui;
  const known = Boolean(snap && snap.total > 0);
  const snapPct = snap && snap.total > 0 ? Math.min(100, (snap.downloaded / snap.total) * 100) : 0;
  const pct = known ? Math.round(paused ? snapPct : dlPct) : null;
  const barPct = paused ? snapPct : dlPct;
  // Bytes are in → the uninterruptible install phase (gate/quit/atomic swap on
  // mac, sideload/extract on Windows). Say so and drop the dead buttons rather
  // than leave them greyed for no visible reason.
  const finishing =
    !paused &&
    (operation?.phase === "committing" ||
      operation?.phase === "finishing" ||
      Boolean(snap && snap.total > 0 && snap.downloaded >= snap.total));
  const uninterruptible = failure?.code === "download_stop_uninterruptible";
  // Pause only makes sense mid-transfer; cancel is the "abandon" out and works
  // through the preparing phase too (a backend abort checkpoint honors it), but
  // not once the install has begun.
  const canPause =
    !paused &&
    operation?.interruptible !== false &&
    !uninterruptible &&
    Boolean(dl && dl.total > 0 && dl.downloaded < dl.total) &&
    !downloadStopBusy;
  const canCancel =
    !paused &&
    !finishing &&
    operation?.cancellable !== false &&
    !uninterruptible &&
    !downloadStopBusy;

  const phase = paused
    ? t("progress.paused.title")
    : finishing
      ? t("progress.finishing")
      : snap
        ? t("progress.downloadingFrom", { source: ui?.sourceLabel ?? snap.source })
        : t("progress.preparing");
  const shownSpeed = ui?.bytesPerSecond ?? dlSpeed;
  const systemAction = ui ? t(ACTION_KEYS[ui.systemAction] ?? "progress.action.unknown") : "";

  return (
    <div className="pop">
      <TopBar />
      <div className="scroll" ref={scopeRef}>
        {failure ? <FailureBanner failure={failure} /> : null}
        <div className="hero" style={{ marginTop: 24 }} key={scene}>
          <Ring icon={paused ? "pause" : "loader"} spin={!paused} className="glow" />
          <div className={`headline${paused ? "" : " shimmer"}`}>
            {paused
              ? t("progress.paused.title")
              : installing
                ? t("progress.installing")
                : t("progress.title")}
          </div>
          {!paused ? (
            <div className="sub" aria-live="polite">
              {phase}
            </div>
          ) : null}
          {pct !== null ? (
            <div className="pctbig">
              {pct}
              <span className="pctsign">%</span>
            </div>
          ) : null}
          <div
            className="bar"
            role="progressbar"
            aria-label={installing ? t("progress.installing") : t("progress.title")}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={pct ?? undefined}
            aria-valuetext={pct !== null ? `${pct}% · ${phase}` : phase}
          >
            <div
              className={`bar-fill${pct === null ? " indeterminate" : ""}`}
              style={pct === null ? undefined : { width: `${barPct}%` }}
            />
          </div>
          {known && snap ? (
            <div className="dlmeta">
              {mib(paused ? snap.downloaded : dlBytes)} / {mib(snap.total)}
              {!paused && shownSpeed > 0 ? ` · ${mib(shownSpeed)}/s` : ""}
            </div>
          ) : (
            <div className="dlmeta">{t("progress.totalUnknown")}</div>
          )}
          {ui ? (
            <div className="progress-detail-grid" aria-live="polite">
              <div>
                <span>{t("progress.step")}</span>
                <strong>
                  {ui.stepIndex}/{ui.stepTotal} · {ui.component}
                </strong>
              </div>
              <div>
                <span>{t("progress.systemAction")}</span>
                <strong>{systemAction}</strong>
              </div>
              <div>
                <span>{t("progress.attempt")}</span>
                <strong>
                  {ui.attemptCurrent}/{ui.attemptTotal}
                  {ui.sourceLabel ? ` · ${ui.sourceLabel}` : ""}
                </strong>
              </div>
              <div>
                <span>{t("progress.eta")}</span>
                <strong>
                  {ui.etaSeconds != null ? duration(ui.etaSeconds) : t("progress.etaUnknown")}
                </strong>
              </div>
              <div className={ui.stalled ? "progress-stalled" : undefined}>
                <span>{t("progress.stall")}</span>
                <strong>
                  {duration(ui.stallElapsedSeconds)}
                  {ui.stalled ? ` · ${t("progress.switchPending")}` : ""}
                </strong>
              </div>
              <div>
                <span>{t("progress.interruptibility")}</span>
                <strong>
                  {ui.pointOfNoReturn
                    ? t("progress.pointOfNoReturn")
                    : t("progress.interruptible")}
                </strong>
              </div>
            </div>
          ) : null}
          {operation?.partialOutcome ? (
            <div className="progress-partial" role="status">
              <strong>{operation.partialOutcome.primary}</strong>
              {operation.partialOutcome.warnings.map((warning) => (
                <span key={warning}>{warning}</span>
              ))}
            </div>
          ) : null}
          {operation?.diagnostics ? (
            <DiagnosticReportPanel active initial={operation.diagnostics} />
          ) : null}
          <div className="progress-actions">
            {paused ? (
              <button className="btn primary" onClick={onResume} disabled={downloadStopBusy}>
                <Icon name="play" />
                {t("progress.resume")}
              </button>
            ) : (
              <button className="btn ghost" onClick={onPause} disabled={!canPause}>
                <Icon name="pause" />
                {downloadStop === "pause" ? t("progress.pausePending") : t("progress.pause")}
              </button>
            )}
            <button
              className="btn danger"
              onClick={onCancel}
              disabled={downloadStopBusy || (!paused && !canCancel)}
            >
              <Icon name="close" />
              {downloadStop === "cancel" ? t("progress.cancelPending") : t("progress.cancel")}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
