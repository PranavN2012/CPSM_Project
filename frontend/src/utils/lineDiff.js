/** Line-level diff via LCS — used to render the real before/after IAM
 * policy JSON from a Layer 4 PolicyDraft as a colored two-column diff. */
export function computeLineDiff(oldLines, newLines) {
  const n = oldLines.length, m = newLines.length;
  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = oldLines[i] === newLines[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const left = [], right = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (oldLines[i] === newLines[j]) {
      left.push({ text: oldLines[i], type: "same" });
      right.push({ text: newLines[j], type: "same" });
      i++; j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      left.push({ text: oldLines[i], type: "rm" });
      i++;
    } else {
      right.push({ text: newLines[j], type: "add" });
      j++;
    }
  }
  while (i < n) { left.push({ text: oldLines[i], type: "rm" }); i++; }
  while (j < m) { right.push({ text: newLines[j], type: "add" }); j++; }
  return { left, right };
}

export function toPrettyLines(obj) {
  return JSON.stringify(obj, null, 2).split("\n");
}
