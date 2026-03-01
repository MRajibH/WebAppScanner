export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category =
    | 'xss'
    | 'injection'
    | 'sensitive-data'
    | 'insecure-code'
    | 'authentication'
    | 'nextjs-specific'
    | 'react-specific'
    | 'misconfiguration';

export interface VulnerabilityRule {
    id: string;
    name: string;
    description: string;
    severity: Severity;
    category: Category;
    pattern: RegExp;
    fix: string;
    cwe?: string;
}

export interface Vulnerability {
    id: string;
    ruleId: string;
    name: string;
    description: string;
    severity: Severity;
    category: Category;
    file: string;
    line: number;
    column: number;
    codeSnippet: string;
    fix: string;
    cwe?: string;
}

export interface ScanResult {
    vulnerabilities: Vulnerability[];
    totalFiles: number;
    scannedAt: string;
    duration: number;
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
        total: number;
    };
}

export interface FileInput {
    name: string;
    content: string;
    path: string;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
};

export const CATEGORY_LABELS: Record<Category, string> = {
    xss: 'Cross-Site Scripting (XSS)',
    injection: 'Injection',
    'sensitive-data': 'Sensitive Data Exposure',
    'insecure-code': 'Insecure Code Patterns',
    authentication: 'Authentication & Authorization',
    'nextjs-specific': 'Next.js Security',
    'react-specific': 'React Security',
    misconfiguration: 'Misconfiguration',
};

export const SEVERITY_COLORS: Record<Severity, string> = {
    critical: '#ff1744',
    high: '#ff6d00',
    medium: '#ffc400',
    low: '#2979ff',
    info: '#78909c',
};
