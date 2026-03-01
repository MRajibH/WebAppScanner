'use client';

import { useState, useCallback, useRef, DragEvent, ChangeEvent } from 'react';
import { scanFiles } from '@/lib/scanner/scanner';
import { vulnerabilityRules } from '@/lib/scanner/rules';
import { ScanResult, FileInput, Severity, Category, CATEGORY_LABELS, SEVERITY_COLORS } from '@/lib/scanner/types';

const VALID_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.json', '.css', '.html', '.py', '.php', '.go', '.c', '.cpp', '.h', '.hpp', '.cc', '.cxx'];
const IGNORED_DIRS = ['node_modules', '.next', '.git', 'dist', 'build', '.cache', 'coverage', '__pycache__'];

function isValidFile(name: string, path: string): boolean {
    const ext = '.' + name.split('.').pop()?.toLowerCase();
    if (!VALID_EXTENSIONS.includes(ext)) return false;
    // Skip files inside ignored directories
    for (const dir of IGNORED_DIRS) {
        if (path.includes(`/${dir}/`) || path.startsWith(`${dir}/`)) return false;
    }
    return true;
}

export default function Home() {
    const [inputMode, setInputMode] = useState<'paste' | 'files' | 'folder'>('paste');
    const [codeInput, setCodeInput] = useState('');
    const [files, setFiles] = useState<FileInput[]>([]);
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [expandedCards, setExpandedCards] = useState<Set<string>>(new Set());
    const [activeFilter, setActiveFilter] = useState<Severity | 'all'>('all');
    const [categoryFilter, setCategoryFilter] = useState<Category | 'all'>('all');
    const [dragOver, setDragOver] = useState(false);
    const [showRules, setShowRules] = useState(false);
    const [rulesFilterCat, setRulesFilterCat] = useState<Category | 'all'>('all');
    const [loadingFiles, setLoadingFiles] = useState(false);
    const [loadProgress, setLoadProgress] = useState({ loaded: 0, total: 0 });
    const fileInputRef = useRef<HTMLInputElement>(null);
    const folderInputRef = useRef<HTMLInputElement>(null);
    const resultsRef = useRef<HTMLDivElement>(null);

    const handleFileRead = useCallback((fileList: FileList) => {
        const newFiles: FileInput[] = [];
        const validFiles = Array.from(fileList).filter(f =>
            isValidFile(f.name, f.webkitRelativePath || f.name)
        );

        if (validFiles.length === 0) return;

        setLoadingFiles(true);
        setLoadProgress({ loaded: 0, total: validFiles.length });

        let loaded = 0;
        validFiles.forEach((file) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                newFiles.push({
                    name: file.name,
                    content: e.target?.result as string,
                    path: file.webkitRelativePath || file.name,
                });
                loaded++;
                setLoadProgress({ loaded, total: validFiles.length });
                if (loaded === validFiles.length) {
                    setFiles(prev => [...prev, ...newFiles]);
                    setLoadingFiles(false);
                }
            };
            reader.readAsText(file);
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

    const clearFiles = useCallback(() => {
        setFiles([]);
    }, []);

    const handleScan = useCallback(() => {
        let filesToScan: FileInput[] = [];

        if (inputMode === 'paste' && codeInput.trim()) {
            filesToScan = [{ name: 'pasted-code.tsx', content: codeInput, path: 'pasted-code.tsx' }];
        } else if ((inputMode === 'files' || inputMode === 'folder') && files.length > 0) {
            filesToScan = files;
        } else {
            return;
        }

        setScanning(true);
        setResult(null);
        setExpandedCards(new Set());
        setActiveFilter('all');
        setCategoryFilter('all');

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
        ((inputMode === 'files' || inputMode === 'folder') && files.length > 0);

    // Group rules by category for display
    const rulesByCategory = vulnerabilityRules.reduce((acc, rule) => {
        if (!acc[rule.category]) acc[rule.category] = [];
        acc[rule.category].push(rule);
        return acc;
    }, {} as Record<string, typeof vulnerabilityRules>);

    const filteredRules = rulesFilterCat === 'all'
        ? vulnerabilityRules
        : vulnerabilityRules.filter(r => r.category === rulesFilterCat);

    // Get unique folder names from uploaded files
    const folderStructure = files.reduce((acc, file) => {
        const parts = file.path.split('/');
        if (parts.length > 1) {
            const folder = parts.slice(0, -1).join('/');
            if (!acc.has(folder)) acc.set(folder, 0);
            acc.set(folder, (acc.get(folder) || 0) + 1);
        }
        return acc;
    }, new Map<string, number>());

    return (
        <>
            {/* ===== HEADER ===== */}
            <header className="header">
                <div className="header-logo">
                    <div className="header-logo-icon">🛡️</div>
                    <div>
                        <div className="header-title">SecureScan</div>
                        <div className="header-subtitle">Multi-Language Code Security Scanner</div>
                    </div>
                </div>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    <button
                        className={`rules-toggle-btn ${showRules ? 'active' : ''}`}
                        onClick={() => setShowRules(prev => !prev)}
                    >
                        📜 {showRules ? 'Hide Rules' : 'View All Rules'}
                    </button>
                    <div className="header-badge">v1.0 • {vulnerabilityRules.length} Rules</div>
                </div>
            </header>

            {/* ===== MAIN ===== */}
            <main className="main-container">
                {/* ===== RULES SHOWCASE ===== */}
                {showRules && (
                    <section className="rules-section">
                        <div className="rules-header">
                            <h2 className="rules-title">🔐 All Security Rules ({vulnerabilityRules.length})</h2>
                            <p className="rules-subtitle">
                                Complete list of vulnerability patterns that SecureScan checks for
                            </p>
                        </div>

                        {/* Category Stats */}
                        <div className="rules-category-stats">
                            {(Object.keys(CATEGORY_LABELS) as Category[]).map(cat => {
                                const count = rulesByCategory[cat]?.length || 0;
                                if (count === 0) return null;
                                return (
                                    <button
                                        key={cat}
                                        className={`rules-cat-chip ${rulesFilterCat === cat ? 'active' : ''}`}
                                        onClick={() => setRulesFilterCat(rulesFilterCat === cat ? 'all' : cat)}
                                    >
                                        {CATEGORY_LABELS[cat]} ({count})
                                    </button>
                                );
                            })}
                            {rulesFilterCat !== 'all' && (
                                <button
                                    className="rules-cat-chip clear"
                                    onClick={() => setRulesFilterCat('all')}
                                >
                                    ✕ Clear
                                </button>
                            )}
                        </div>

                        {/* Rules Grid */}
                        <div className="rules-grid">
                            {filteredRules.map((rule, i) => (
                                <div key={rule.id} className="rule-card" style={{ animationDelay: `${i * 30}ms` }}>
                                    <div className="rule-card-header">
                                        <span className={`severity-badge ${rule.severity}`}>
                                            {rule.severity}
                                        </span>
                                        <span className="rule-card-id">{rule.id}</span>
                                        {rule.cwe && <span className="vuln-cwe-tag">{rule.cwe}</span>}
                                    </div>
                                    <h4 className="rule-card-name">{rule.name}</h4>
                                    <p className="rule-card-desc">{rule.description}</p>
                                    <div className="rule-card-category">
                                        {CATEGORY_LABELS[rule.category]}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </section>
                )}

                {/* ===== HERO ===== */}
                <section className="hero">
                    <h1 className="hero-title">
                        Scan Your Code for
                        <br />
                        Security Vulnerabilities
                    </h1>
                    <p className="hero-description">
                        Detect XSS, injection flaws, hardcoded secrets, buffer overflows, and
                        security issues across JavaScript, Python, PHP, Go, and C/C++ instantly.
                    </p>
                    <div className="hero-features">
                        <span className="hero-feature">
                            <span className="hero-feature-icon">⚡</span> Instant Analysis
                        </span>
                        <span className="hero-feature">
                            <span className="hero-feature-icon">🔍</span> {vulnerabilityRules.length} Security Rules
                        </span>
                        <span className="hero-feature">
                            <span className="hero-feature-icon">🎯</span> Multi-Language Support
                        </span>
                        <span className="hero-feature">
                            <span className="hero-feature-icon">📁</span> Full Folder Upload
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
                            className={`input-tab ${inputMode === 'files' ? 'active' : ''}`}
                            onClick={() => setInputMode('files')}
                        >
                            📄 Upload Files
                        </button>
                        <button
                            className={`input-tab ${inputMode === 'folder' ? 'active' : ''}`}
                            onClick={() => setInputMode('folder')}
                        >
                            🗂️ Upload Folder
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
                    ) : inputMode === 'files' ? (
                        <>
                            <div
                                className={`file-uploader ${dragOver ? 'drag-over' : ''}`}
                                onDrop={handleDrop}
                                onDragOver={handleDragOver}
                                onDragLeave={handleDragLeave}
                                onClick={() => fileInputRef.current?.click()}
                            >
                                <div className="file-uploader-icon">📄</div>
                                <div className="file-uploader-title">
                                    Drop files here or click to browse
                                </div>
                                <div className="file-uploader-text">
                                    Upload individual React & Next.js source files
                                </div>
                                <div className="file-uploader-formats">
                                    JS/TS, Python, PHP, Go, C/C++, JSON, CSS, HTML
                                </div>
                                <input
                                    ref={fileInputRef}
                                    type="file"
                                    multiple
                                    accept=".ts,.tsx,.js,.jsx,.mjs,.cjs,.json,.css,.html,.py,.php,.go,.c,.cpp,.h,.hpp,.cc,.cxx"
                                    onChange={handleFileSelect}
                                    style={{ display: 'none' }}
                                />
                            </div>
                            {files.length > 0 && (
                                <>
                                    <div className="file-list-header">
                                        <span className="file-list-count">{files.length} file{files.length !== 1 ? 's' : ''} selected</span>
                                        <button className="file-clear-btn" onClick={clearFiles}>✕ Clear all</button>
                                    </div>
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
                                </>
                            )}
                        </>
                    ) : (
                        <>
                            <div
                                className={`file-uploader folder-uploader ${dragOver ? 'drag-over' : ''}`}
                                onDrop={handleDrop}
                                onDragOver={handleDragOver}
                                onDragLeave={handleDragLeave}
                                onClick={() => folderInputRef.current?.click()}
                            >
                                <div className="file-uploader-icon">🗂️</div>
                                <div className="file-uploader-title">
                                    Click to select a project folder
                                </div>
                                <div className="file-uploader-text">
                                    Upload your entire React or Next.js project folder
                                </div>
                                <div className="file-uploader-formats">
                                    Scans JS/TS, Python, PHP, Go, C/C++ and more — recursively
                                </div>
                                <div className="folder-upload-hints">
                                    <span className="folder-hint">✅ Auto-skips node_modules, .next, .git, dist</span>
                                    <span className="folder-hint">✅ Preserves folder structure in results</span>
                                </div>
                                <input
                                    ref={folderInputRef}
                                    type="file"
                                    /* @ts-expect-error webkitdirectory is not in TypeScript types */
                                    webkitdirectory="true"
                                    directory="true"
                                    multiple
                                    onChange={handleFileSelect}
                                    style={{ display: 'none' }}
                                />
                            </div>
                            {files.length > 0 && (
                                <>
                                    <div className="file-list-header">
                                        <span className="file-list-count">
                                            📁 {files.length} file{files.length !== 1 ? 's' : ''} loaded
                                            {folderStructure.size > 0 && ` from ${folderStructure.size} folder${folderStructure.size !== 1 ? 's' : ''}`}
                                        </span>
                                        <button className="file-clear-btn" onClick={clearFiles}>✕ Clear all</button>
                                    </div>
                                    {/* Folder tree */}
                                    <div className="folder-tree">
                                        {Array.from(folderStructure.entries())
                                            .sort(([a], [b]) => a.localeCompare(b))
                                            .slice(0, 20)
                                            .map(([folder, count]) => (
                                                <div key={folder} className="folder-tree-item">
                                                    <span className="folder-tree-icon">📁</span>
                                                    <span className="folder-tree-path">{folder}</span>
                                                    <span className="folder-tree-count">{count} file{count !== 1 ? 's' : ''}</span>
                                                </div>
                                            ))}
                                        {folderStructure.size > 20 && (
                                            <div className="folder-tree-item more">
                                                ...and {folderStructure.size - 20} more folders
                                            </div>
                                        )}
                                    </div>
                                    {/* File chips */}
                                    <div className="file-list">
                                        {files.slice(0, 50).map((file, index) => (
                                            <div key={index} className="file-chip">
                                                📄 {file.path}
                                                <button
                                                    className="file-chip-remove"
                                                    onClick={() => removeFile(index)}
                                                >
                                                    ✕
                                                </button>
                                            </div>
                                        ))}
                                        {files.length > 50 && (
                                            <div className="file-chip more-chip">
                                                +{files.length - 50} more files
                                            </div>
                                        )}
                                    </div>
                                </>
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
                            Checking for {vulnerabilityRules.length} vulnerability patterns across 8 categories
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
                                    Your code passed all {vulnerabilityRules.length} security checks. Great job keeping your code secure!
                                </div>
                            </div>
                        ) : (
                            <div className="vuln-list">
                                {filteredVulnerabilities.map((vuln, index) => (
                                    <div
                                        key={vuln.id}
                                        className="vuln-card"
                                        style={{ animationDelay: `${Math.min(index * 50, 500)}ms` }}
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

                {/* ===== FILE LOADING OVERLAY ===== */}
                {loadingFiles && (
                    <div className="file-loading-overlay">
                        <div className="file-loading-card">
                            <div className="file-loading-spinner" />
                            <div className="file-loading-title">Loading files...</div>
                            <div className="file-loading-progress">
                                {loadProgress.loaded} / {loadProgress.total} files processed
                            </div>
                            <div className="file-loading-bar-track">
                                <div
                                    className="file-loading-bar-fill"
                                    style={{ width: `${loadProgress.total > 0 ? (loadProgress.loaded / loadProgress.total) * 100 : 0}%` }}
                                />
                            </div>
                        </div>
                    </div>
                )}
            </main>

            {/* ===== FOOTER ===== */}
            <footer className="app-footer">
                <div className="footer-content">
                    <div className="footer-copyright">
                        © {new Date().getFullYear()} <strong>Muhammad Rajib Hawlader</strong>. All rights reserved.
                    </div>
                    <div className="footer-links">
                        <a href="https://rajib.uk" target="_blank" rel="noopener noreferrer" className="footer-link">
                            🌐 rajib.uk
                        </a>
                        <span className="footer-divider">•</span>
                        <span className="footer-app-name">SecureScan v1.0</span>
                    </div>
                </div>
            </footer>
        </>
    );
}
