import { useCallback, useEffect, useState } from "react";

/** Persists light/dark theme to localStorage and toggles the data-theme
 * attribute style.css keys off.
 *
 * style.css only defines a `[data-theme="dark"]` override block — bare
 * `:root` already holds the light values as its defaults, with no
 * `[data-theme="light"]` rule at all. So the attribute must be SET for dark
 * mode and REMOVED (or left unset) for light mode. This was previously
 * inverted (set "light", remove for dark) — the exact opposite of what the
 * CSS checks — which meant clicking the toggle to switch to dark mode
 * stripped the attribute and left the light `:root` defaults in effect:
 * the toggle visibly did nothing. */
export function useTheme() {
  const [isLight, setIsLight] = useState(true);

  const applyTheme = (light) => {
    if (light) {
      document.documentElement.removeAttribute("data-theme");
    } else {
      document.documentElement.setAttribute("data-theme", "dark");
    }
  };

  useEffect(() => {
    const stored = localStorage.getItem("theme") || "light";
    const light = stored === "light";
    applyTheme(light);
    setIsLight(light);
  }, []);

  const toggleTheme = useCallback(() => {
    setIsLight((prev) => {
      const next = !prev;
      applyTheme(next);
      localStorage.setItem("theme", next ? "light" : "dark");
      return next;
    });
  }, []);

  return { isLight, toggleTheme };
}
