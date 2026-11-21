/**
 * FeatureTable Component.
 * Displays extracted 29 features with values and status indicators.
 */

export function renderFeatureTable(features) {
  if (!features) return "<p class='text-gray-400'>No features available.</p>";

  const rows = Object.entries(features).map(([key, value]) => {
    let badge = `<span class="text-gray-300">${value}</span>`;
    if (typeof value === "number" && value > 0 && (key.includes("has_") || key.includes("suspicious") || key.includes("is_shortened"))) {
      badge = `<span class="text-red-400 font-semibold">${value} (Flagged)</span>`;
    } else if (key === "is_https" && value === 1) {
      badge = `<span class="text-green-400 font-semibold">1 (Encrypted)</span>`;
    }

    return `
      <tr class="border-b border-slate-700/50 hover:bg-slate-800/50">
        <td class="py-2 px-3 font-mono text-xs text-sky-300">${key}</td>
        <td class="py-2 px-3 text-xs">${badge}</td>
      </tr>
    `;
  }).join("");

  return `
    <div class="overflow-x-auto max-h-80 overflow-y-auto rounded border border-slate-700">
      <table class="w-full text-left border-collapse">
        <thead>
          <tr class="bg-slate-800 text-slate-400 text-xs uppercase font-semibold">
            <th class="py-2 px-3">Engineered Feature</th>
            <th class="py-2 px-3">Extracted Value</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>
  `;
}
