import { useEffect, useRef, useState } from "react";

/** Eases from the previous displayed value to `value` over 500ms,
 * matching the original vanilla animateValue() cubic ease-out. */
export default function AnimatedNumber({ value, suffix = "" }) {
  const [display, setDisplay] = useState(0);
  const prevRef = useRef(0);
  const frameRef = useRef(null);

  useEffect(() => {
    const target = parseFloat(value) || 0;
    const start = prevRef.current;
    const diff = target - start;
    if (diff === 0) {
      setDisplay(target);
      return;
    }
    const duration = 500;
    const startTime = performance.now();

    function tick(now) {
      const progress = Math.min((now - startTime) / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      const val = Math.round((start + diff * ease) * 10) / 10;
      setDisplay(val);
      if (progress < 1) {
        frameRef.current = requestAnimationFrame(tick);
      } else {
        setDisplay(target);
        prevRef.current = target;
      }
    }
    frameRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frameRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  return <>{Math.round(display)}{suffix}</>;
}
