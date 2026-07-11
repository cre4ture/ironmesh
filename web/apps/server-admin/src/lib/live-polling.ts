import { useEffect, useState } from "react";

export type LivePollingMode = "live" | "passive" | "hidden";

type PollIntervalProfile = {
  live: number | false;
  passive?: number | false;
  hidden?: number | false;
};

type UseLivePollingModeOptions = {
  idleMs?: number;
};

type UseViewportVisibilityOptions = {
  initialVisible?: boolean;
  rootMargin?: string;
  threshold?: number;
};

export function useLivePollingMode(
  options: UseLivePollingModeOptions = {}
): LivePollingMode {
  const { idleMs = 45_000 } = options;
  const [isDocumentVisible, setIsDocumentVisible] = useState(() =>
    typeof document === "undefined" ? true : document.visibilityState === "visible"
  );
  const [isWindowFocused, setIsWindowFocused] = useState(() =>
    typeof document === "undefined" ? true : document.hasFocus()
  );
  const [isUserActive, setIsUserActive] = useState(true);

  useEffect(() => {
    if (typeof window === "undefined" || typeof document === "undefined") {
      return;
    }

    let idleTimeoutId = 0;

    const scheduleIdle = () => {
      window.clearTimeout(idleTimeoutId);
      idleTimeoutId = window.setTimeout(() => {
        setIsUserActive(false);
      }, idleMs);
    };

    const markActive = () => {
      setIsUserActive(true);
      scheduleIdle();
    };

    const handleVisibilityChange = () => {
      const visible = document.visibilityState === "visible";
      setIsDocumentVisible(visible);
      if (visible) {
        markActive();
      } else {
        setIsUserActive(false);
      }
    };

    const handleFocus = () => {
      setIsWindowFocused(true);
      markActive();
    };

    const handleBlur = () => {
      setIsWindowFocused(false);
    };

    markActive();
    setIsDocumentVisible(document.visibilityState === "visible");
    setIsWindowFocused(document.hasFocus());

    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("focus", handleFocus);
    window.addEventListener("blur", handleBlur);
    window.addEventListener("pointerdown", markActive, { passive: true });
    window.addEventListener("keydown", markActive);
    window.addEventListener("scroll", markActive, { passive: true });
    window.addEventListener("touchstart", markActive, { passive: true });

    return () => {
      window.clearTimeout(idleTimeoutId);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("focus", handleFocus);
      window.removeEventListener("blur", handleBlur);
      window.removeEventListener("pointerdown", markActive);
      window.removeEventListener("keydown", markActive);
      window.removeEventListener("scroll", markActive);
      window.removeEventListener("touchstart", markActive);
    };
  }, [idleMs]);

  if (!isDocumentVisible) {
    return "hidden";
  }

  if (!isWindowFocused || !isUserActive) {
    return "passive";
  }

  return "live";
}

export function resolveLivePollInterval(
  mode: LivePollingMode,
  profile: PollIntervalProfile
): number | false {
  if (mode === "live") {
    return profile.live;
  }

  if (mode === "passive") {
    return profile.passive ?? profile.live;
  }

  return profile.hidden ?? false;
}

export function useViewportVisibility<T extends Element>(
  options: UseViewportVisibilityOptions = {}
): {
  isVisible: boolean;
  ref: (node: T | null) => void;
} {
  const {
    initialVisible = true,
    rootMargin = "0px",
    threshold = 0
  } = options;
  const [node, setNode] = useState<T | null>(null);
  const [isVisible, setIsVisible] = useState(initialVisible);

  useEffect(() => {
    if (node === null) {
      return;
    }

    if (typeof IntersectionObserver === "undefined") {
      setIsVisible(true);
      return;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        setIsVisible(entry?.isIntersecting ?? false);
      },
      {
        root: null,
        rootMargin,
        threshold
      }
    );

    observer.observe(node);

    return () => {
      observer.disconnect();
    };
  }, [node, rootMargin, threshold]);

  return {
    isVisible,
    ref: setNode
  };
}
