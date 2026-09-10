import { Chart as ChartJS, ArcElement, BarElement, LineElement, PointElement,
  CategoryScale, LinearScale, Tooltip, Legend, Filler } from "chart.js";

ChartJS.register(ArcElement, BarElement, LineElement, PointElement,
  CategoryScale, LinearScale, Tooltip, Legend, Filler);

export const COLORS = {
  cyan: "rgba(8, 117, 160, 0.88)",
  blue: "rgba(79, 70, 229, 0.88)",
  purple: "rgba(99, 91, 238, 0.88)",
  emerald: "rgba(5, 150, 105, 0.88)",
  rose: "rgba(198, 31, 37, 0.88)",
  amber: "rgba(202, 138, 4, 0.88)",
  glass: "rgba(79, 70, 229, 0.1)",
};

/** Applies the dark/light Chart.js theme, matching the original
 * updateChartTheme(). Called once on mount and whenever isLight changes. */
export function applyChartTheme(isLight) {
  if (isLight) {
    ChartJS.defaults.color = "#64748b";
    ChartJS.defaults.scale.grid.color = "rgba(0, 0, 0, 0.05)";
    ChartJS.defaults.plugins.tooltip.backgroundColor = "rgba(255, 255, 255, 0.95)";
    ChartJS.defaults.plugins.tooltip.titleColor = "#171717";
    ChartJS.defaults.plugins.tooltip.bodyColor = "#525252";
    ChartJS.defaults.plugins.tooltip.borderColor = "rgba(79, 70, 229, 0.2)";
  } else {
    ChartJS.defaults.color = "#94a3b8";
    ChartJS.defaults.scale.grid.color = "rgba(255, 255, 255, 0.05)";
    ChartJS.defaults.plugins.tooltip.backgroundColor = "rgba(16, 20, 31, 0.9)";
    ChartJS.defaults.plugins.tooltip.titleColor = "#ffffff";
    ChartJS.defaults.plugins.tooltip.bodyColor = "#fff";
    ChartJS.defaults.plugins.tooltip.borderColor = "rgba(255, 255, 255, 0.1)";
  }
  ChartJS.defaults.font.family = "'Inter', system-ui, sans-serif";
  ChartJS.defaults.plugins.tooltip.padding = 12;
  ChartJS.defaults.plugins.tooltip.cornerRadius = 4;
  ChartJS.defaults.plugins.tooltip.borderWidth = 1;
}
