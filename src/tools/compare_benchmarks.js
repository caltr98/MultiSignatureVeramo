import fs from 'fs';
import path from 'path';
function parseArg(name, defaultValue) {
    const index = process.argv.indexOf(`--${name}`);
    if (index !== -1 && process.argv[index + 1])
        return process.argv[index + 1];
    return defaultValue;
}
function parseNumber(value, ctx) {
    const n = Number(value);
    if (!Number.isFinite(n))
        throw new Error(`Invalid number for ${ctx}: ${value}`);
    return n;
}
function parseCsvLines(filePath) {
    const raw = fs.readFileSync(filePath, 'utf-8');
    return raw
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean)
        .map((line) => line.split(',').map((c) => c.trim()));
}
function loadBlsBenchmark(filePath) {
    // Format: Issuers,StepName,avg_ms,std_ms (but often without a header)
    const lines = parseCsvLines(filePath);
    const first = lines[0];
    const hasHeader = first?.[0]?.toLowerCase() === 'issuers';
    const rows = hasHeader ? lines.slice(1) : lines;
    return rows.map((cols, i) => {
        if (cols.length < 4) {
            throw new Error(`Invalid row in ${filePath} at line ${i + 1}: ${cols.join(',')}`);
        }
        return {
            scheme: 'bls-multisig',
            issuers: parseNumber(cols[0], 'issuers'),
            stepName: cols[1],
            avgMs: parseNumber(cols[2], 'avg_ms'),
            stdMs: parseNumber(cols[3], 'std_ms'),
        };
    });
}
function loadEipBenchmark(filePath) {
    // Format with header: Issuers,StepName,avg_ms,std_ms
    const lines = parseCsvLines(filePath);
    if (lines.length === 0)
        return [];
    const first = lines[0];
    const hasHeader = first?.[0]?.toLowerCase() === 'issuers';
    const rows = hasHeader ? lines.slice(1) : lines;
    return rows.map((cols, i) => {
        if (cols.length < 4) {
            throw new Error(`Invalid row in ${filePath} at line ${i + 1}: ${cols.join(',')}`);
        }
        return {
            scheme: 'eip712-baseline',
            issuers: parseNumber(cols[0], 'issuers'),
            stepName: cols[1],
            avgMs: parseNumber(cols[2], 'avg_ms'),
            stdMs: parseNumber(cols[3], 'std_ms'),
        };
    });
}
function writeMergedCsv(outPath, rows) {
    const header = 'Scheme,Issuers,StepName,avg_ms,std_ms\n';
    const body = rows
        .slice()
        .sort((a, b) => a.issuers - b.issuers || a.scheme.localeCompare(b.scheme) || a.stepName.localeCompare(b.stepName))
        .map((r) => `${r.scheme},${r.issuers},${r.stepName},${r.avgMs},${r.stdMs}`)
        .join('\n');
    fs.writeFileSync(outPath, header + body + '\n');
}
function aggregateRows(rows) {
    const grouped = new Map();
    for (const r of rows) {
        const key = `${r.scheme}::${r.issuers}::${r.stepName}`;
        const existing = grouped.get(key);
        if (existing) {
            existing.avg.push(r.avgMs);
            existing.std.push(r.stdMs);
        }
        else {
            grouped.set(key, { scheme: r.scheme, issuers: r.issuers, stepName: r.stepName, avg: [r.avgMs], std: [r.stdMs] });
        }
    }
    const mean = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length;
    return [...grouped.values()].map((g) => ({
        scheme: g.scheme,
        issuers: g.issuers,
        stepName: g.stepName,
        avgMs: mean(g.avg),
        stdMs: mean(g.std),
    }));
}
function printTotals(rows) {
    const totals = new Map();
    for (const r of rows) {
        const key = `${r.scheme}::${r.issuers}`;
        totals.set(key, (totals.get(key) ?? 0) + r.avgMs);
    }
    const entries = [...totals.entries()]
        .map(([key, totalMs]) => {
        const [scheme, issuers] = key.split('::');
        return { scheme, issuers: Number(issuers), totalMs };
    })
        .sort((a, b) => a.issuers - b.issuers || a.scheme.localeCompare(b.scheme));
    console.log('\nTotals (sum of avg_ms across all steps in the file):');
    console.table(entries.map((e) => ({
        Scheme: e.scheme,
        Issuers: e.issuers,
        total_ms: Number(e.totalMs.toFixed(6)),
    })));
}
const blsPath = parseArg('bls', 'experimental_results/benchmark_results_claims16_size64.csv');
const eipPath = parseArg('eip', 'experimental_results/benchmark_standard_eip712_claims16_size64.csv');
const outPath = parseArg('out', 'experimental_results/benchmark_compare.csv');
const outAggPath = parseArg('outAgg');
const blsAbs = path.resolve(blsPath);
const eipAbs = path.resolve(eipPath);
const outAbs = path.resolve(outPath);
const outAggAbs = path.resolve(outAggPath || outPath.replace(/\.csv$/i, '_agg.csv'));
const rowsRaw = [...loadBlsBenchmark(blsAbs), ...loadEipBenchmark(eipAbs)];
const rowsAgg = aggregateRows(rowsRaw);
writeMergedCsv(outAbs, rowsRaw);
writeMergedCsv(outAggAbs, rowsAgg);
printTotals(rowsAgg);
console.log(`\nWrote merged CSV (raw rows): ${outAbs}`);
console.log(`Wrote merged CSV (aggregated): ${outAggAbs}`);
