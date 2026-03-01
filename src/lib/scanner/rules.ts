import { VulnerabilityRule } from './types';

export const vulnerabilityRules: VulnerabilityRule[] = [
    // ==================== XSS ====================
    {
        id: 'XSS-001',
        name: 'dangerouslySetInnerHTML Usage',
        description:
            'Using dangerouslySetInnerHTML can lead to Cross-Site Scripting (XSS) attacks if the HTML content is not properly sanitized.',
        severity: 'critical',
        category: 'xss',
        pattern: /dangerouslySetInnerHTML\s*=\s*\{/g,
        fix: 'Use a sanitization library like DOMPurify to sanitize HTML content before rendering, or use safer alternatives like rendering text content directly.',
        cwe: 'CWE-79',
    },
    {
        id: 'XSS-002',
        name: 'innerHTML Assignment',
        description:
            'Direct assignment to innerHTML can introduce XSS vulnerabilities if user-controlled data is used.',
        severity: 'critical',
        category: 'xss',
        pattern: /\.innerHTML\s*=\s*/g,
        fix: 'Use textContent or innerText instead, or sanitize the HTML with DOMPurify before assignment.',
        cwe: 'CWE-79',
    },
    {
        id: 'XSS-003',
        name: 'outerHTML Assignment',
        description:
            'Direct assignment to outerHTML can introduce XSS vulnerabilities.',
        severity: 'high',
        category: 'xss',
        pattern: /\.outerHTML\s*=\s*/g,
        fix: 'Avoid using outerHTML with user-controlled data. Use DOM manipulation methods instead.',
        cwe: 'CWE-79',
    },
    {
        id: 'XSS-004',
        name: 'document.write Usage',
        description:
            'document.write can be exploited for XSS if user input is passed to it.',
        severity: 'high',
        category: 'xss',
        pattern: /document\.write\s*\(/g,
        fix: 'Use DOM manipulation methods like createElement and appendChild instead of document.write.',
        cwe: 'CWE-79',
    },
    {
        id: 'XSS-005',
        name: 'Unsanitized URL in href/src',
        description:
            'Using javascript: protocol in href or src attributes can lead to XSS.',
        severity: 'critical',
        category: 'xss',
        pattern: /(?:href|src)\s*=\s*[{"`'].*javascript\s*:/gi,
        fix: 'Validate and sanitize URLs. Never allow javascript: protocol in user-provided URLs.',
        cwe: 'CWE-79',
    },

    // ==================== INJECTION ====================
    {
        id: 'INJ-001',
        name: 'eval() Usage',
        description:
            'eval() executes arbitrary code and is a major security risk, especially with user-controlled input.',
        severity: 'critical',
        category: 'injection',
        pattern: /\beval\s*\(/g,
        fix: 'Replace eval() with JSON.parse() for JSON data, or use safer alternatives like Function constructors with proper input validation.',
        cwe: 'CWE-94',
    },
    {
        id: 'INJ-002',
        name: 'Function Constructor',
        description:
            'The Function constructor can execute arbitrary code similar to eval().',
        severity: 'high',
        category: 'injection',
        pattern: /new\s+Function\s*\(/g,
        fix: 'Avoid using the Function constructor with dynamic strings. Use predefined functions or safe alternatives.',
        cwe: 'CWE-94',
    },
    {
        id: 'INJ-003',
        name: 'setTimeout/setInterval with String',
        description:
            'Passing strings to setTimeout/setInterval is equivalent to eval() and can execute arbitrary code.',
        severity: 'high',
        category: 'injection',
        pattern: /(?:setTimeout|setInterval)\s*\(\s*["'`]/g,
        fix: 'Pass a function reference instead of a string to setTimeout/setInterval.',
        cwe: 'CWE-94',
    },
    {
        id: 'INJ-004',
        name: 'SQL Injection Pattern',
        description:
            'String concatenation in SQL queries can lead to SQL injection attacks.',
        severity: 'critical',
        category: 'injection',
        pattern: /(?:query|execute|exec)\s*\(\s*[`"'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\$\{/gi,
        fix: 'Use parameterized queries or prepared statements instead of string concatenation.',
        cwe: 'CWE-89',
    },
    {
        id: 'INJ-005',
        name: 'Command Injection',
        description:
            'Using exec, execSync, or spawn with user input can lead to command injection.',
        severity: 'critical',
        category: 'injection',
        pattern: /(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(?:`[^`]*\$\{|[^)]*\+\s*(?:req|params|query|body|input|user))/g,
        fix: 'Validate and sanitize user input before passing to shell commands. Use parameterized execution or allowlists.',
        cwe: 'CWE-78',
    },
    {
        id: 'INJ-006',
        name: 'Template Injection in SQL',
        description:
            'Using template literals in database queries without parameterization enables injection attacks.',
        severity: 'critical',
        category: 'injection',
        pattern: /\b(?:prisma|knex|sequelize|db|pool|client)\s*\.(?:\$queryRaw|raw|query)\s*\(\s*`[^`]*\$\{/gi,
        fix: 'Use parameterized queries. For Prisma use Prisma.sql tagged template. For Knex use .where() bindings.',
        cwe: 'CWE-89',
    },

    // ==================== SENSITIVE DATA EXPOSURE ====================
    {
        id: 'SDE-001',
        name: 'Hardcoded API Key',
        description:
            'API keys hardcoded in source code can be exposed in version control and client bundles.',
        severity: 'critical',
        category: 'sensitive-data',
        pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["'`][A-Za-z0-9_\-]{16,}/gi,
        fix: 'Move API keys to environment variables (.env.local) and access them via process.env. Never commit secrets to version control.',
        cwe: 'CWE-798',
    },
    {
        id: 'SDE-002',
        name: 'Hardcoded Password',
        description:
            'Hardcoded passwords in source code are a severe security risk.',
        severity: 'critical',
        category: 'sensitive-data',
        pattern: /(?:password|passwd|pwd|secret)\s*[:=]\s*["'`][^"'`\s]{4,}/gi,
        fix: 'Use environment variables or a secret management service for passwords. Never hardcode credentials.',
        cwe: 'CWE-798',
    },
    {
        id: 'SDE-003',
        name: 'Hardcoded Token/Secret',
        description:
            'Tokens and secrets should never be hardcoded in source code.',
        severity: 'critical',
        category: 'sensitive-data',
        pattern: /(?:token|secret|private[_-]?key|access[_-]?key)\s*[:=]\s*["'`][A-Za-z0-9_\-/.+=]{16,}/gi,
        fix: 'Store tokens and secrets in environment variables or a secrets manager like AWS Secrets Manager or HashiCorp Vault.',
        cwe: 'CWE-798',
    },
    {
        id: 'SDE-004',
        name: 'Exposed Environment Variable in Client Code',
        description:
            'Environment variables without the NEXT_PUBLIC_ prefix accessed in client components will be undefined, but those with it are exposed to the browser.',
        severity: 'medium',
        category: 'sensitive-data',
        pattern: /process\.env\.NEXT_PUBLIC_(?:SECRET|KEY|TOKEN|PASSWORD|API_KEY|PRIVATE)/gi,
        fix: 'Never expose sensitive values via NEXT_PUBLIC_ prefix. Only use NEXT_PUBLIC_ for genuinely public configuration values.',
        cwe: 'CWE-200',
    },
    {
        id: 'SDE-005',
        name: 'Console Logging Sensitive Data',
        description:
            'Logging sensitive data like passwords, tokens, or keys can expose them in production.',
        severity: 'medium',
        category: 'sensitive-data',
        pattern: /console\.(?:log|info|debug|warn|error)\s*\([^)]*(?:password|token|secret|key|credential|auth)/gi,
        fix: 'Remove console logging of sensitive data. Use a proper logging framework with data masking in production.',
        cwe: 'CWE-532',
    },

    // ==================== INSECURE CODE ====================
    {
        id: 'IC-001',
        name: 'Weak Cryptography (MD5)',
        description:
            'MD5 is cryptographically broken and should not be used for security purposes.',
        severity: 'high',
        category: 'insecure-code',
        pattern: /(?:createHash|crypto\.(?:subtle\.)?digest)\s*\(\s*["'`]md5["'`]/gi,
        fix: 'Use SHA-256 or stronger algorithms for hashing. Use bcrypt or argon2 for password hashing.',
        cwe: 'CWE-328',
    },
    {
        id: 'IC-002',
        name: 'Weak Cryptography (SHA1)',
        description:
            'SHA-1 is considered weak and vulnerable to collision attacks.',
        severity: 'medium',
        category: 'insecure-code',
        pattern: /(?:createHash|crypto\.(?:subtle\.)?digest)\s*\(\s*["'`]sha1["'`]/gi,
        fix: 'Use SHA-256 or SHA-3 for hashing operations.',
        cwe: 'CWE-328',
    },
    {
        id: 'IC-003',
        name: 'Math.random() for Security',
        description:
            'Math.random() is not cryptographically secure and should not be used for generating tokens, IDs, or secrets.',
        severity: 'medium',
        category: 'insecure-code',
        pattern: /Math\.random\s*\(\s*\)/g,
        fix: 'Use crypto.randomBytes() or crypto.randomUUID() for generating secure random values.',
        cwe: 'CWE-338',
    },
    {
        id: 'IC-004',
        name: 'Disabled ESLint Rule',
        description:
            'Disabling ESLint security rules may hide potential vulnerabilities.',
        severity: 'low',
        category: 'insecure-code',
        pattern: /\/\/\s*eslint-disable(?:-next-line)?.*(?:no-eval|no-implied-eval|no-new-func|security)/g,
        fix: 'Address the underlying issue instead of disabling security-related ESLint rules.',
        cwe: 'CWE-710',
    },
    {
        id: 'IC-005',
        name: 'TypeScript @ts-ignore',
        description:
            'Using @ts-ignore suppresses type checking which could hide type-safety vulnerabilities.',
        severity: 'low',
        category: 'insecure-code',
        pattern: /\/\/\s*@ts-ignore/g,
        fix: 'Fix the underlying TypeScript error instead of suppressing it. Use @ts-expect-error if suppression is truly necessary.',
        cwe: 'CWE-710',
    },
    {
        id: 'IC-006',
        name: 'Unsafe Type Assertion (any)',
        description:
            'Using "as any" bypasses TypeScript type checking and can introduce runtime errors.',
        severity: 'low',
        category: 'insecure-code',
        pattern: /\bas\s+any\b/g,
        fix: 'Define proper TypeScript types/interfaces instead of using "as any" assertions.',
        cwe: 'CWE-710',
    },

    // ==================== AUTHENTICATION ====================
    {
        id: 'AUTH-001',
        name: 'Missing CSRF Protection',
        description:
            'API endpoints handling state-changing operations without CSRF tokens are vulnerable to Cross-Site Request Forgery.',
        severity: 'high',
        category: 'authentication',
        pattern: /export\s+(?:async\s+)?function\s+(?:POST|PUT|DELETE|PATCH)\s*\(/g,
        fix: 'Implement CSRF token validation for state-changing API routes. Use a library like csrf or implement token-based verification.',
        cwe: 'CWE-352',
    },
    {
        id: 'AUTH-002',
        name: 'Insecure Cookie Settings',
        description:
            'Cookies without httpOnly, secure, or sameSite attributes are vulnerable to theft and misuse.',
        severity: 'high',
        category: 'authentication',
        pattern: /(?:set-cookie|setCookie|cookies?\(\)\.set)\s*\([^)]*(?!httpOnly|secure|sameSite)/gi,
        fix: 'Set httpOnly: true, secure: true, and sameSite: "strict" on all authentication cookies.',
        cwe: 'CWE-614',
    },
    {
        id: 'AUTH-003',
        name: 'JWT Secret in Code',
        description:
            'JWT signing secrets should never be hardcoded in application code.',
        severity: 'critical',
        category: 'authentication',
        pattern: /jwt\.sign\s*\([^)]*["'`][A-Za-z0-9_\-]{8,}["'`]/g,
        fix: 'Store JWT secrets in environment variables and use asymmetric key pairs (RS256) when possible.',
        cwe: 'CWE-798',
    },
    {
        id: 'AUTH-004',
        name: 'No Auth Check in API Route',
        description:
            'API route handlers without authentication checks can be accessed by unauthorized users.',
        severity: 'medium',
        category: 'authentication',
        pattern: /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\s*\(\s*(?:req|request)[^)]*\)\s*\{(?:(?!auth|session|token|getServerSession|getToken|verify|middleware)[\s\S]){0,500}\}/g,
        fix: 'Add authentication and authorization checks at the beginning of API route handlers using NextAuth.js or similar.',
        cwe: 'CWE-306',
    },

    // ==================== NEXT.JS SPECIFIC ====================
    {
        id: 'NEXT-001',
        name: 'Exposed Server-Side Data',
        description:
            'Returning excessive data from getServerSideProps or getStaticProps can leak sensitive server-side information to the client.',
        severity: 'high',
        category: 'nextjs-specific',
        pattern: /(?:getServerSideProps|getStaticProps)\s*(?::\s*\w+\s*)?\(\s*\)\s*\{[\s\S]*?return\s*\{[\s\S]*?props\s*:\s*\{[\s\S]*?(?:password|secret|token|key|internal|private)/gi,
        fix: 'Only return the minimum necessary data in props. Filter out any sensitive information before returning.',
        cwe: 'CWE-200',
    },
    {
        id: 'NEXT-002',
        name: 'Missing Security Headers',
        description:
            'Next.js apps should configure security headers for protection against common attacks.',
        severity: 'medium',
        category: 'nextjs-specific',
        pattern: /next\.config\.\s*(?:js|mjs|ts)/g,
        fix: 'Add security headers in next.config.js: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, and Strict-Transport-Security.',
        cwe: 'CWE-693',
    },
    {
        id: 'NEXT-003',
        name: 'Disabled React Strict Mode',
        description:
            'React Strict Mode helps identify potential problems. It should be enabled in production.',
        severity: 'low',
        category: 'nextjs-specific',
        pattern: /reactStrictMode\s*:\s*false/g,
        fix: 'Set reactStrictMode: true in next.config.js to enable additional development checks.',
        cwe: 'CWE-710',
    },
    {
        id: 'NEXT-004',
        name: 'Exposed Source Maps in Production',
        description:
            'Source maps in production expose your original source code to attackers.',
        severity: 'medium',
        category: 'nextjs-specific',
        pattern: /productionBrowserSourceMaps\s*:\s*true/g,
        fix: 'Set productionBrowserSourceMaps: false or remove the setting to prevent source code exposure.',
        cwe: 'CWE-200',
    },
    {
        id: 'NEXT-005',
        name: 'Unvalidated Redirect',
        description:
            'Using redirect() or router.push() with user-controlled URLs can lead to open redirect attacks.',
        severity: 'high',
        category: 'nextjs-specific',
        pattern: /(?:redirect|router\.push|router\.replace)\s*\(\s*(?:req\.query|req\.body|searchParams|params\[)/g,
        fix: 'Validate redirect URLs against a whitelist of allowed destinations. Never redirect to user-controlled URLs directly.',
        cwe: 'CWE-601',
    },
    {
        id: 'NEXT-006',
        name: 'Unsafe Image Domain Configuration',
        description:
            'Using wildcard patterns in Next.js image domains allows loading images from any source.',
        severity: 'medium',
        category: 'nextjs-specific',
        pattern: /images\s*:\s*\{[\s\S]*?(?:remotePatterns|domains)\s*:\s*\[[\s\S]*?\*[\s\S]*?\]/g,
        fix: 'Specify explicit allowed image domains instead of using wildcards.',
        cwe: 'CWE-942',
    },
    {
        id: 'NEXT-007',
        name: 'Server Action Without Validation',
        description:
            'Server actions that directly use form data without validation are vulnerable to injection and data corruption.',
        severity: 'high',
        category: 'nextjs-specific',
        pattern: /["']use server["'][\s\S]*?(?:formData|FormData)[\s\S]*?(?:\.get\s*\(|\.getAll\s*\()(?![\s\S]*?(?:zod|yup|joi|validate|schema|parse))/g,
        fix: 'Validate all form data inputs using a validation library like Zod before processing in server actions.',
        cwe: 'CWE-20',
    },

    // ==================== REACT SPECIFIC ====================
    {
        id: 'REACT-001',
        name: 'findDOMNode Usage',
        description:
            'findDOMNode is deprecated and can cause unexpected behavior. It breaks abstraction and can cause security issues.',
        severity: 'medium',
        category: 'react-specific',
        pattern: /(?:ReactDOM\.)?findDOMNode\s*\(/g,
        fix: 'Use React refs (useRef hook or createRef) instead of findDOMNode.',
        cwe: 'CWE-477',
    },
    {
        id: 'REACT-002',
        name: 'String Refs Usage',
        description:
            'String refs are deprecated and have several issues including security concerns.',
        severity: 'low',
        category: 'react-specific',
        pattern: /ref\s*=\s*["'`][a-zA-Z]/g,
        fix: 'Use callback refs or useRef/createRef instead of string refs.',
        cwe: 'CWE-477',
    },
    {
        id: 'REACT-003',
        name: 'Uncontrolled Component with Sensitive Data',
        description:
            'Uncontrolled inputs for sensitive fields like passwords may not properly clear data from the DOM.',
        severity: 'medium',
        category: 'react-specific',
        pattern: /defaultValue\s*=\s*\{[^}]*(?:password|secret|token|key)/gi,
        fix: 'Use controlled components for sensitive data inputs to ensure proper data handling and cleanup.',
        cwe: 'CWE-200',
    },
    {
        id: 'REACT-004',
        name: 'useEffect with Sensitive Data Dependency',
        description:
            'Including sensitive data as useEffect dependencies can lead to unexpected re-renders and data exposure.',
        severity: 'low',
        category: 'react-specific',
        pattern: /useEffect\s*\(\s*(?:(?:\(\s*\)\s*=>|function\s*\(\s*\))\s*\{[\s\S]*?(?:password|secret|token|apiKey)[\s\S]*?\})\s*,\s*\[[\s\S]*?(?:password|secret|token|apiKey)/gi,
        fix: 'Avoid using sensitive data as useEffect dependencies. If necessary, derive a non-sensitive value for the dependency.',
        cwe: 'CWE-200',
    },

    // ==================== MISCONFIGURATION ====================
    {
        id: 'MISC-001',
        name: 'CORS Allow All Origins',
        description:
            'Setting Access-Control-Allow-Origin to "*" allows any website to make requests to your API.',
        severity: 'high',
        category: 'misconfiguration',
        pattern: /(?:Access-Control-Allow-Origin|allowedOrigins?)\s*[:=]\s*["'`]\*["'`]/g,
        fix: 'Specify allowed origins explicitly instead of using a wildcard. Use a whitelist of trusted domains.',
        cwe: 'CWE-942',
    },
    {
        id: 'MISC-002',
        name: 'Debug Mode Enabled',
        description:
            'Debug mode or verbose error messages in production can expose sensitive application details.',
        severity: 'medium',
        category: 'misconfiguration',
        pattern: /(?:debug|DEBUG)\s*[:=]\s*true/g,
        fix: 'Ensure debug mode is disabled in production. Use environment-based configuration to toggle debug settings.',
        cwe: 'CWE-489',
    },
    {
        id: 'MISC-003',
        name: 'Permissive Content Security Policy',
        description:
            "Using 'unsafe-inline' or 'unsafe-eval' in CSP weakens its protection against XSS.",
        severity: 'high',
        category: 'misconfiguration',
        pattern: /(?:Content-Security-Policy|CSP)[\s\S]*?(?:unsafe-inline|unsafe-eval)/gi,
        fix: "Remove 'unsafe-inline' and 'unsafe-eval' from your CSP. Use nonces or hashes for inline scripts.",
        cwe: 'CWE-693',
    },
    {
        id: 'MISC-004',
        name: 'HTTP Instead of HTTPS',
        description:
            'Using HTTP URLs for API calls or resources exposes data to man-in-the-middle attacks.',
        severity: 'medium',
        category: 'misconfiguration',
        pattern: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g,
        fix: 'Use HTTPS for all external API calls and resource URLs to ensure encrypted communication.',
        cwe: 'CWE-319',
    },
    {
        id: 'MISC-005',
        name: 'Exposed Error Stack Trace',
        description:
            'Sending raw error objects or stack traces to the client reveals internal implementation details.',
        severity: 'medium',
        category: 'misconfiguration',
        pattern: /(?:res|response)\.(?:json|send|status)\s*\([^)]*(?:err\.stack|error\.stack|\.stack)/g,
        fix: 'Return generic error messages to clients. Log detailed error information server-side only.',
        cwe: 'CWE-209',
    },
    {
        id: 'MISC-006',
        name: 'Prototype Pollution Risk',
        description:
            'Using Object.assign or spread with user input on objects can lead to prototype pollution.',
        severity: 'high',
        category: 'misconfiguration',
        pattern: /Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:req\.body|req\.query|params|input|body)/g,
        fix: 'Validate and sanitize user input before merging. Use Object.create(null) for prototype-free objects or validate against a schema.',
        cwe: 'CWE-1321',
    },
    {
        id: 'MISC-007',
        name: 'Unrestricted File Upload',
        description:
            'Accepting file uploads without proper validation can lead to arbitrary file execution.',
        severity: 'high',
        category: 'misconfiguration',
        pattern: /(?:multer|formidable|busboy|multiparty)\s*\(\s*\{(?:(?!fileFilter|limits|allowedExtensions)[\s\S])*?\}\s*\)/g,
        fix: 'Validate file types, sizes, and names. Restrict allowed file extensions and scan for malware.',
        cwe: 'CWE-434',
    },
];
