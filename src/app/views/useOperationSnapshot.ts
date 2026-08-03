import { useEffect, useState } from "react";

import { managerApi } from "../../services/managerApi";
import type { OperationSnapshot } from "../../shared/types";

/** Backend-authoritative operation view for both locally started and reattached work. */
export function useOperationSnapshot(active: boolean): OperationSnapshot | null {
  const [snapshot, setSnapshot] = useState<OperationSnapshot | null>(null);

  useEffect(() => {
    if (!active) {
      setSnapshot(null);
      return;
    }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const poll = () => {
      void managerApi
        .getOperationSnapshot()
        .then((next) => {
          if (cancelled) return;
          setSnapshot(next);
          timer = setTimeout(poll, 500);
        })
        .catch(() => {
          if (cancelled) return;
          timer = setTimeout(poll, 800);
        });
    };
    poll();
    return () => {
      cancelled = true;
      if (timer != null) clearTimeout(timer);
    };
  }, [active]);

  return snapshot;
}
