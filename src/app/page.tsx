'use client';

import { useState, useCallback, useRef, DragEvent, ChangeEvent } from 'react';
import { scanFiles } from '@/lib/scanner/scanner';
import { ScanResult, FileInput, Severity, Category, CATEGORY_LABELS } from '@/lib/scanner/types';

export default function Home() {
    const [inputMode, setInputMode] = useState<'paste' | 'upload'>('paste');
    const [codeInput, setCodeInput] = useState('');
    const [files, setFiles] = useState<FileInput[]>([]);
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [expandedCards, setExpandedCards] = useState<Set<string>>(new Set());
    const [activeFilter, setActiveFilter] = useState<Severity | 'all'>('all');
    const [categoryFilter, setCategoryFilter] = useState<Category | 'all'>('all');
    const [dragOver, setDragOver] = useState(false);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const resultsRef = useRef<HTMLDivElement>(null);

    const handleFileRead = useCallback((fileList: FileList) => {
        const newFiles: FileInput[] = [];
        const validExtensions = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.json', '.css', '.html'];

        Array.from(fileList).forEach((file) => {
            const ext = '.' + file.name.split('.').pop()?.toLowerCase();
            if (validExtensions.includes(ext)) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    newFiles.push({
                        name: file.name,
                        content: e.target?.result as string,
                        path: file.webkitRelativePath || file.name,
                    });
                    if (newFiles.length === Array.from(fileList).filter(f => validExtensions.includes('.' + f.name.split('.').pop()?.toLowerCase())).length) {
                        setFiles(prev => [...prev, ...newFiles]);
                    }
                };
                reader.readAsText(file);
            }
        });
    }, []);

    const handleDrop = useCallback(
        (e: DragEvent<HTMLDivElement>) => {
            e.preventDefault();
            setDragOver(false);
            if (e.dataTransfer.files.length > 0) {
                handleFileRead(e.dataTransfer.files);
            }
        },
        [handleFileRead]
    );

    const handleDragOver = useCallback((e: DragEvent<HTMLDivElement>) => {
        e.preventDefault();
        setDragOver(true);
    }, []);

    const handleDragLeave = useCallback(() => {
        setDragOver(false);
    }, []);

    const handleFileSelect = useCallback(
        (e: ChangeEvent<HTMLInputElement>) => {
            if (e.target.files && e.target.files.length > 0) {
                handleFileRead(e.target.files);
            }
        },
        [handleFileRead]
    );

    const removeFile = useCallback((index: number) => {
        setFiles(prev => prev.filter((_, i) => i !== index));
    }, []);

    const handleScan = useCallback(() => {
        let filesToScan: FileInput[] = [];

        if (inputMode === 'paste' && codeInput.trim()) {
            filesToScan = [{ name: 'pasted-code.tsx', content: codeInput, path: 'pasted-code.tsx' }];
        } else if (inputMode === 'upload' && files.length > 0) {
            filesToScan = files;
        } else {
            return;
        }

        setScanning(true);
        setResult(null);
        setExpandedCards(new Set());
        setActiveFilter('all');
        setCategoryFilter('all');

        // Run scan client-side with a small delay for animation
        setTimeout(() => {
            const scanResult = scanFiles(filesToScan);
            setResult(scanResult);
            setScanning(false);

            setTimeout(() => {
                resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 100);
        }, 300);
    }, [inputMode, codeInput, files]);

    const toggleCard = useCallback((id: string) => {
        setExpandedCards(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    }, []);

    const exportResults = useCallback(() => {
        if (!result) return;
        const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-scan-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }, [result]);

    const filteredVulnerabilities = result?.vulnerabilities.filter(v => {
        if (activeFilter !== 'all' && v.severity !== activeFilter) return false;
        if (categoryFilter !== 'all' && v.category !== categoryFilter) return false;
        return true;
    }) || [];

    const canScan =
        (inputMode === 'paste' && codeInput.trim().length > 0) ||
        (inputMode === 'upload' && files.length > 0);

    return (
        <>
            {/* ===== HEADER ===== */}
            <header className="header">
                <div className="header-logo">
                    <div className="header-logo-icon">🛡️</div>
                    <div>
                        <div className="header-title">SecureScan</div>
                        <div className="header-subtitle">React & Next.js Security Scanner</div>
                    </div>
                </div>
                <div className="header-badge">v1.0 • 40+ Rules</div>
            </header>

            {/* ===== MAIN ===== */}
            <main className="main-container">
                {/* ===== HERO ===== */}
                <section className="hero">
                    <h1 className="hero-title">
                        Scan Your Code for
                        <br />
                        Security Vulnerabilities
                    </h1>
                    <p className="hero-description">
                        Detect XSS, injection flaws, hardcoded secrets, misconfigurations, and
                        React/Next.js-specific security issues in your codebase instantly.
                    </p>
                    <div className="hero-features">
                        <span className="hero-feature">
                            <span className="hero-feature-icon">⚡</span> Instant Analysis
                        </span>
                        <span className="hero-feature">
                            <span className="hero-feature-icon">🔍</span> 40+ Security Rules
                        </span>
                        <span className="hero-feature">
                            <span className="hero-feature-icon">🎯</span> Next.js & React Specific
                        </span>
                        <span className="hero-feature">
                            <span className="hero-feature-icon">📋</span> Actionable Fixes
                        </span>
                    </div>
                </section>

                {/* ===== SCANNER INPUT ===== */}
                <section className="scanner-section">
                    <div className="input-tabs">
                        <button
                            className={`input-tab ${inputMode === 'paste' ? 'active' : ''}`}
                            onClick={() => setInputMode('paste')}
                        >
                            📝 Paste Code
                        </button>
                        <button
                            className={`input-tab ${inputMode === 'upload' ? 'active' : ''}`}
                            onClick={() => setInputMode('upload')}
                        >
                            📁 Upload Files
                        </button>
                    </div>

                    {inputMode === 'paste' ? (
                        <div className="code-editor-wrapper">
                            <div className="code-editor-header">
                                <div className="code-editor-dots">
                                    <span className="code-editor-dot red" />
                                    <span className="code-editor-dot yellow" />
                                    <span className="code-editor-dot green" />
                                </div>
                                <span className="code-editor-filename">pasted-code.tsx</span>
                                <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
                                    {codeInput.split('\n').length} lines
                                </span>
                            </div>
                            <textarea
                                className="code-editor-textarea"
                                placeholder={`// Paste your React or Next.js code here...\n// Example:\nimport { useEffect } from 'react';\n\nexport default function Page() {\n  const apiKey = "sk-1234567890abcdef";\n  return <div dangerouslySetInnerHTML={{__html: userInput}} />;\n}`}
                                value={codeInput}
                                onChange={(e) => setCodeInput(e.target.value)}
                                spellCheck={false}
                            />
                        </div>
                    ) : (
                        <>
                            <div
                                className={`file-uploader ${dragOver ? 'drag-over' : ''}`}
                                onDrop={handleDrop}
                                onDragOver={handleDragOver}
                                onDragLeave={handleDragLeave}
                                onClick={() => fileInputRef.current?.click()}
                            >
                                <div className="file-uploader-icon">📂</div>
                                <div className="file-uploader-title">
                                    Drop files here or click to browse
                                </div>
                                <div className="file-uploader-text">
                                    Upload your React & Next.js source files
                                </div>
                                <div className="file-uploader-formats">
                                    Supported: .ts, .tsx, .js, .jsx, .mjs, .cjs, .json, .css, .html
                                </div>
                                <input
                                    ref={fileInputRef}
                                    type="file"
                                    multiple
                                    accept=".ts,.tsx,.js,.jsx,.mjs,.cjs,.json,.css,.html"
                                    onChange={handleFileSelect}
                                    style={{ display: 'none' }}
                                />
                            </div>
                            {files.length > 0 && (
                                <div className="file-list">
                                    {files.map((file, index) => (
                                        <div key={index} className="file-chip">
                                            📄 {file.name}
                                            <button
                                                className="file-chip-remove"
                                                onClick={() => removeFile(index)}
                                            >
                                                ✕
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </>
                    )}

                    <div className="scan-button-container">
                        <button
                            className={`scan-button ${scanning ? 'scanning' : ''}`}
                            onClick={handleScan}
                            disabled={!canScan || scanning}
                        >
                            {scanning ? (
                                <>
                                    <span className="spinner" />
                                    Scanning...
                                </>
                            ) : (
                                '🔒 Start Security Scan'
                            )}
                        </button>
                    </div>
                </section>

                {/* ===== SCANNING ANIMATION ===== */}
                {scanning && (
                    <div className="scanning-overlay">
                        <div className="scanning-icon">🔍</div>
                        <div className="scanning-text">Analyzing your code...</div>
                        <div className="scanning-subtext">
                            Checking for 40+ vulnerability patterns across 8 categories
                        </div>
                    </div>
                )}

                {/* ===== RESULTS ===== */}
                {result && !scanning && (
                    <section className="results-section" ref={resultsRef}>
                        <div className="results-header">
                            <h2 className="results-title">Scan Results</h2>
                            <div className="results-meta">
                                <span className="results-meta-item">
                                    📁 {result.totalFiles} file{result.totalFiles !== 1 ? 's' : ''} scanned
                                </span>
                                <span className="results-meta-item">
                                    ⏱️ {result.duration}ms
                                </span>
                                <button className="export-button" onClick={exportResults}>
                                    📥 Export JSON
                                </button>
                            </div>
                        </div>

                        {/* Summary Dashboard */}
                        <div className="summary-dashboard">
                            <div
                                className={`summary-card total ${activeFilter === 'all' ? 'active' : ''}`}
                                onClick={() => setActiveFilter('all')}
                                style={{ animationDelay: '0ms' }}
                            >
                                <div className="summary-count">{result.summary.total}</div>
                                <div className="summary-label">Total</div>
                            </div>
                            <div
                                className={`summary-card critical ${activeFilter === 'critical' ? 'active' : ''}`}
                                onClick={() => setActiveFilter('critical')}
                                style={{ animationDelay: '50ms' }}
                            >
                                <div className="summary-count">{result.summary.critical}</div>
                                <div className="summary-label">Critical</div>
                            </div>
                            <div
                                className={`summary-card high ${activeFilter === 'high' ? 'active' : ''}`}
                                onClick={() => setActiveFilter('high')}
                                style={{ animationDelay: '100ms' }}
                            >
                                <div className="summary-count">{result.summary.high}</div>
                                <div className="summary-label">High</div>
                            </div>
                            <div
                                className={`summary-card medium ${activeFilter === 'medium' ? 'active' : ''}`}
                                onClick={() => setActiveFilter('medium')}
                                style={{ animationDelay: '150ms' }}
                            >
                                <div className="summary-count">{result.summary.medium}</div>
                                <div className="summary-label">Medium</div>
                            </div>
                            <div
                                className={`summary-card low ${activeFilter === 'low' ? 'active' : ''}`}
                                onClick={() => setActiveFilter('low')}
                                style={{ animationDelay: '200ms' }}
                            >
                                <div className="summary-count">{result.summary.low}</div>
                                <div className="summary-label">Low</div>
                            </div>
                            <div
                                className={`summary-card info ${activeFilter === 'info' ? 'active' : ''}`}
                                onClick={() => setActiveFilter('info')}
                                style={{ animationDelay: '250ms' }}
                            >
                                <div className="summary-count">{result.summary.info}</div>
                                <div className="summary-label">Info</div>
                            </div>
                        </div>

                        {/* Category Filters */}
                        {result.summary.total > 0 && (
                            <div className="filter-bar">
                                <span className="filter-label">Category:</span>
                                <button
                                    className={`filter-chip ${categoryFilter === 'all' ? 'active' : ''}`}
                                    onClick={() => setCategoryFilter('all')}
                                >
                                    All
                                </button>
                                {(Object.keys(CATEGORY_LABELS) as Category[]).map((cat) => {
                                    const count = result.vulnerabilities.filter(v => v.category === cat).length;
                                    if (count === 0) return null;
                                    return (
                                        <button
                                            key={cat}
                                            className={`filter-chip ${categoryFilter === cat ? 'active' : ''}`}
                                            onClick={() => setCategoryFilter(cat)}
                                        >
                                            {CATEGORY_LABELS[cat]} ({count})
                                        </button>
                                    );
                                })}
                            </div>
                        )}

                        {/* Vulnerability List */}
                        {result.summary.total === 0 ? (
                            <div className="no-results">
                                <div className="no-results-icon">🎉</div>
                                <div className="no-results-title">No Vulnerabilities Found!</div>
                                <div className="no-results-text">
                                    Your code passed all 40+ security checks. Great job keeping your code secure!
                                </div>
                            </div>
                        ) : (
                            <div className="vuln-list">
                                {filteredVulnerabilities.map((vuln, index) => (
                                    <div
                                        key={vuln.id}
                                        className="vuln-card"
                                        style={{ animationDelay: `${index * 50}ms` }}
                                    >
                                        <div
                                            className="vuln-card-header"
                                            onClick={() => toggleCard(vuln.id)}
                                        >
                                            <div className={`vuln-card-severity-indicator ${vuln.severity}`} />
                                            <div className="vuln-card-info">
                                                <div className="vuln-card-top-row">
                                                    <span className="vuln-card-name">{vuln.name}</span>
                                                    <span className={`severity-badge ${vuln.severity}`}>
                                                        {vuln.severity}
                                                    </span>
                                                    <span className="vuln-card-rule-id">{vuln.ruleId}</span>
                                                    {vuln.cwe && (
                                                        <span className="vuln-cwe-tag">{vuln.cwe}</span>
                                                    )}
                                                </div>
                                                <div className="vuln-card-location">
                                                    📄 {vuln.file} : line {vuln.line}
                                                </div>
                                            </div>
                                            <span className={`vuln-card-expand ${expandedCards.has(vuln.id) ? 'open' : ''}`}>
                                                ▼
                                            </span>
                                        </div>

                                        {expandedCards.has(vuln.id) && (
                                            <div className="vuln-card-details">
                                                <div className="vuln-detail-section">
                                                    <div className="vuln-detail-label">Description</div>
                                                    <div className="vuln-detail-text">{vuln.description}</div>
                                                </div>

                                                <div className="vuln-detail-section">
                                                    <div className="vuln-detail-label">Code</div>
                                                    <div className="vuln-code-snippet">
                                                        <pre>{vuln.codeSnippet}</pre>
                                                    </div>
                                                </div>

                                                <div className="vuln-detail-section">
                                                    <div className="vuln-detail-label">💡 How to Fix</div>
                                                    <div className="vuln-fix-box">{vuln.fix}</div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                ))}

                                {filteredVulnerabilities.length === 0 && (
                                    <div className="no-results">
                                        <div className="no-results-icon">🔎</div>
                                        <div className="no-results-title">No matches</div>
                                        <div className="no-results-text">
                                            No vulnerabilities match the current filter. Try adjusting your filters.
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </section>
                )}
            </main>
        </>
    );
}
