/**
 * ThreatBadge Component.
 */

export function renderThreatBadge(threatLevel, confidence) {
  const percentage = Math.round(confidence * 100);
  let colorClass = "bg-green-600";
  let label = "SAFE";

  if (threatLevel === "PHISHING") {
    colorClass = "bg-red-600";
    label = "PHISHING ATTACK";
  } else if (threatLevel === "SUSPICIOUS") {
    colorClass = "bg-amber-600";
    label = "SUSPICIOUS";
  }

  return `
    <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold text-white ${colorClass}">
      <span class="w-2 h-2 rounded-full bg-white animate-pulse"></span>
      <span>${label} (${percentage}%)</span>
    </div>
  `;
}
