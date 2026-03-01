import { vulnerabilityRules } from './rules';
import { FileInput, ScanResult, Vulnerability, Severity } from './types';

let idCounter = 0;

function generateId(): string {
    idCounter += 1;
    return `vuln-${Date.now()}-${idCounter}`;
}

function getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
}

function getColumn(content: string, index: number): number {
    const beforeMatch = content.substring(0, index);
    const lastNewline = beforeMatch.lastIndexOf('\n');
    return index - lastNewline;
}

function getCodeSnippet(
    content: string,
    lineNumber: number,
    contextLines: number = 2
): string {
    const lines = content.split('\n');
    const start = Math.max(0, lineNumber - contextLines - 1);
    const end = Math.min(lines.length, lineNumber + contextLines);
    return lines
        .slice(start, end)
        .map((line, i) => {
            const ln = start + i + 1;
            const marker = ln === lineNumber ? '>' : ' ';
            return `${marker} ${ln.toString().padStart(4)} | ${line}`;
        })
        .join('\n');
}

export function scanFile(file: FileInput): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const rule of vulnerabilityRules) {
        const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
        let match: RegExpExecArray | null;

        while ((match = regex.exec(file.content)) !== null) {
            const lineNumber = getLineNumber(file.content, match.index);
            const column = getColumn(file.content, match.index);

            // Check if the match is inside a single-line comment
            // We do this by getting the current line's text up to the match index
            // and checking if it contains '//'
            const currentLineBeforeMatch = file.content.substring(match.index - column, match.index);

            // If the line has '//' before our match, we skip it
            // (Unless the rule specifically targets comments, e.g., eslint-disable checks)
            if (currentLineBeforeMatch.includes('//') && !rule.pattern.source.includes('\\/\\/')) {
                continue;
            }

            const codeSnippet = getCodeSnippet(file.content, lineNumber);

            vulnerabilities.push({
                id: generateId(),
                ruleId: rule.id,
                name: rule.name,
                description: rule.description,
                severity: rule.severity,
                category: rule.category,
                file: file.path || file.name,
                line: lineNumber,
                column,
                codeSnippet,
                fix: rule.fix,
                cwe: rule.cwe,
            });
        }
    }

    return vulnerabilities;
}

export function scanFiles(files: FileInput[]): ScanResult {
    const startTime = Date.now();
    idCounter = 0;

    const allVulnerabilities: Vulnerability[] = [];

    for (const file of files) {
        const fileVulns = scanFile(file);
        allVulnerabilities.push(...fileVulns);
    }

    // Sort by severity
    const severityOrder: Record<Severity, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 4,
    };

    allVulnerabilities.sort(
        (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
    );

    const summary = {
        critical: allVulnerabilities.filter((v) => v.severity === 'critical').length,
        high: allVulnerabilities.filter((v) => v.severity === 'high').length,
        medium: allVulnerabilities.filter((v) => v.severity === 'medium').length,
        low: allVulnerabilities.filter((v) => v.severity === 'low').length,
        info: allVulnerabilities.filter((v) => v.severity === 'info').length,
        total: allVulnerabilities.length,
    };

    return {
        vulnerabilities: allVulnerabilities,
        totalFiles: files.length,
        scannedAt: new Date().toISOString(),
        duration: Date.now() - startTime,
        summary,
    };
}
