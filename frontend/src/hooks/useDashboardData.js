import { useCallback, useEffect, useRef, useState } from "react";
import { fetchEvents, fetchStats, fetchCompliance } from "../api.js";

const REFRESH_INTERVAL_MS = 30_000;

/** Polls /events, /stats, /compliance on an interval, exposing a manual
 * refresh() for the header's refresh button. Mirrors the original
 * vanilla app.js refresh loop 1:1. */
export function useDashboardData() {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [compliance, setCompliance] = useState(null);
  const [connected, setConnected] = useState(false);
  const intervalRef = useRef(null);

  const refresh = useCallback(async () => {
    try {
      const evts = await fetchEvents();
      setEvents(evts);
      const s = await fetchStats();
      setStats(s);
      setConnected(true);

      const comp = await fetchCompliance();
      setCompliance(comp);
    } catch (err) {
      console.error("Refresh error:", err);
      setConnected(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    intervalRef.current = setInterval(refresh, REFRESH_INTERVAL_MS);
    return () => clearInterval(intervalRef.current);
  }, [refresh]);

  return { events, stats, compliance, connected, refresh };
}
