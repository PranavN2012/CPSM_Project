import { useState } from "react";
import PixelSwap from "./PixelSwap.jsx";
import SplitFlapText from "./SplitFlapText.jsx";
import LightRays from "./LightRays.jsx";
import { useTheme } from "../hooks/useTheme.js";

/** One-shot cinematic entry screen: a black "CloudSentry" button that
 * pixel-dissolves into the real app on click. Rendered by main.jsx ONLY
 * until the reveal completes — main.jsx then swaps to rendering <App/>
 * directly and this component (and PixelSwap along with it) is fully
 * unmounted, never wrapping the real dashboard. That's deliberate: PixelSwap's
 * outer container is `overflow:hidden` and a stacking-context root, which
 * would be safe for a one-time splash but is exactly the kind of thing that
 * quietly breaks dropdowns/modals/scroll if it stuck around forever. */
export default function IntroGate({ onRevealed }) {
  // Sets document.documentElement's data-theme attribute immediately on
  // mount (before <App/> exists at all), so the revealed background color
  // below matches the user's actual light/dark preference with no flash.
  useTheme();
  const [active, setActive] = useState(false);

  return (
    <PixelSwap
      active={active}
      onActiveChange={setActive}
      onComplete={(to) => {
        if (to) onRevealed?.();
      }}
      firstContent={
        <div className="intro-gate__splash">
          <div className="intro-gate__rays">
            <LightRays
              raysOrigin="top-center"
              raysColor="#4f46e5"
              raysSpeed={1}
              lightSpread={0.8}
              rayLength={3}
              followMouse
              mouseInfluence={0.2}
              noiseAmount={0}
              distortion={0}
              pulsating={false}
              fadeDistance={0.5}
              saturation={1}
            />
          </div>
          <button className="intro-gate__button" type="button" tabIndex={-1}>
            <SplitFlapText
              words={["", "CLOUDSENTRY"]}
              loop={false}
              cycleDelay={250}
              flipDuration={0.11}
              stagger={0.045}
              flipsPerChar={10}
              tileColor="#0a0a0a"
              textColor="#f8fafc"
              tileRadius={10}
              gap={5}
              fontSize={56}
              padTo={11}
              className="intro-gate__title"
            />
            <span className="intro-gate__tagline">Detect. Decide. Defend.</span>
          </button>
        </div>
      }
      secondContent={<div className="intro-gate__reveal" />}
      pixelSize={56}
      gap={0}
      pixelRadius={0}
      pixelSpin={0}
      pixelScale={0.9}
      duration={1100}
      pixelDuration={450}
      pattern="center"
      randomness={0}
      fade
      trigger="click"
      aspectRatio="auto"
      className="intro-gate"
      style={{ position: "fixed", inset: 0, width: "100vw", height: "100vh", zIndex: 9999 }}
    />
  );
}
