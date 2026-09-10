import React, { useState } from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import IntroGate from "./components/IntroGate.jsx";
import "./style.css";

// IntroGate is only ever mounted here, before the first reveal — once
// revealed, this swaps to rendering <App/> alone, so the cinematic intro
// (and everything about how PixelSwap lays out its container) never touches
// any other page.
function Root() {
  const [revealed, setRevealed] = useState(false);
  return revealed ? <App /> : <IntroGate onRevealed={() => setRevealed(true)} />;
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
);
