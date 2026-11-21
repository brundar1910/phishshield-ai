/**
 * ModelMetricsChart Component.
 * Formats model comparison metrics into responsive HTML tables and bar charts.
 */

export function renderModelComparison(metricsData) {
  if (!metricsData || !metricsData.models) {
    return "<p class='text-gray-400'>No model metrics available.</p>";
  }

  const models = metricsData.models;
  const rows = Object.entries(models).map(([name, m]) => {
    const isChampion = name === metricsData.champion_model;
    const championBadge = isChampion ? "<span class='ml-2 px-2 py-0.5 text-xs bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded'>CHAMPION</span>" : "";

    return `
      <tr class="border-b border-slate-700/60 hover:bg-slate-800/40">
        <td class="py-3 px-4 font-semibold text-slate-200">${name} ${championBadge}</td>
        <td class="py-3 px-4 font-mono text-emerald-400">${(m.accuracy * 100).toFixed(1)}%</td>
        <td class="py-3 px-4 font-mono text-sky-400">${(m.precision * 100).toFixed(1)}%</td>
        <td class="py-3 px-4 font-mono text-amber-400">${(m.recall * 100).toFixed(1)}%</td>
        <td class="py-3 px-4 font-mono text-purple-400">${(m.f1_score * 100).toFixed(1)}%</td>
        <td class="py-3 px-4 font-mono text-cyan-400">${(m.roc_auc * 100).toFixed(1)}%</td>
      </tr>
    `;
  }).join("");

  return `
    <div class="overflow-x-auto rounded-lg border border-slate-700 bg-slate-900/60">
      <table class="w-full text-left border-collapse text-sm">
        <thead>
          <tr class="bg-slate-800/80 text-slate-400 text-xs uppercase font-medium">
            <th class="py-3 px-4">Classifier</th>
            <th class="py-3 px-4">Accuracy</th>
            <th class="py-3 px-4">Precision</th>
            <th class="py-3 px-4">Recall</th>
            <th class="py-3 px-4">F1-Score</th>
            <th class="py-3 px-4">ROC-AUC</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>
  `;
}
