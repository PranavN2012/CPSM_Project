import { useState } from "react";
import DecryptedText from "./DecryptedText.jsx";

export default function Topbar({ connected, isLight, onToggleTheme, onRefresh }) {
  const [spinning, setSpinning] = useState(false);
  const [downloading, setDownloading] = useState(false);

  function handleRefresh() {
    setSpinning(true);
    onRefresh();
    setTimeout(() => setSpinning(false), 500);
  }

  function handleDownloadReport() {
    setDownloading(true);
    window.open("/report", "_blank");
    setTimeout(() => setDownloading(false), 3000);
  }

  return (
    <header className="topbar reveal-element">
      <div className="topbar__left">
        <span className="topbar__cloud">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
            <path d="M17.5 19H8a5 5 0 1 1 1.7-9.71A6 6 0 0 1 21 11.5a4.5 4.5 0 0 1-3.5 7.5z" />
          </svg>
        </span>
        <span className="topbar__crumb">CloudSentry <b>/</b></span>
        <h1 className="topbar__title">
          <DecryptedText text="Operations" animateOn="view" sequential revealDirection="start" speed={26} encryptedClassName="dtx-scramble" />
          <br />
          <DecryptedText text="Console" animateOn="view" sequential revealDirection="start" speed={26} encryptedClassName="dtx-scramble" />
        </h1>
      </div>
      <div className="topbar__right">
        <span className="status-indicator">
          <span className={`status-dot${connected ? "" : " status-dot--error"}`}></span>
          <span className="status-text">{connected ? "Live • Auto-refresh 30s" : "API Unreachable"}</span>
        </span>
        <span className="topbar__badge" title="LocalStack AWS Emulation">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
            <rect x="3" y="4" width="18" height="14" rx="2" /><path d="M3 9h18M8 4v5" />
          </svg>
          LocalStack AWS Emulation
        </span>
        <button className="btn-glass" title="Download PDF Report" disabled={downloading} onClick={handleDownloadReport}>
          <span>{downloading ? "Generating..." : "Audit Export"}</span>
        </button>
        <button className="btn-icon" title="Toggle Theme" onClick={onToggleTheme}>
          {isLight ? (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="12" cy="12" r="5"></circle>
              <line x1="12" y1="1" x2="12" y2="3"></line>
              <line x1="12" y1="21" x2="12" y2="23"></line>
              <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
              <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
              <line x1="1" y1="12" x2="3" y2="12"></line>
              <line x1="21" y1="12" x2="23" y2="12"></line>
              <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
              <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
            </svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
            </svg>
          )}
        </button>
        <button
          className="btn-icon"
          title="Refresh"
          onClick={handleRefresh}
          style={{ transform: spinning ? "rotate(360deg)" : "", transition: "transform 0.5s" }}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.59-9.21l5.25 1.64" />
          </svg>
        </button>
      </div>
    </header>
  );
}
