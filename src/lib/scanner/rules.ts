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

    // ==================== PYTHON SPECIFIC ====================
    {
        id: 'PY-001',
        name: 'Python eval() Usage',
        description:
            'eval() executes arbitrary Python code and is extremely dangerous with user input.',
        severity: 'critical',
        category: 'python-specific',
        pattern: /\beval\s*\(\s*(?:request|input|sys\.argv|os\.environ|data|params|args)/g,
        fix: 'Use ast.literal_eval() for safe evaluation of literals, or parse input explicitly.',
        cwe: 'CWE-94',
    },
    {
        id: 'PY-002',
        name: 'Python exec() Usage',
        description:
            'exec() executes arbitrary Python code, enabling code injection attacks.',
        severity: 'critical',
        category: 'python-specific',
        pattern: /\bexec\s*\(/g,
        fix: 'Avoid exec() entirely. Use structured approaches like safe parsers or predefined functions.',
        cwe: 'CWE-94',
    },
    {
        id: 'PY-003',
        name: 'Python os.system() Command Injection',
        description:
            'os.system() passes commands to the shell, enabling command injection.',
        severity: 'critical',
        category: 'python-specific',
        pattern: /os\.system\s*\(/g,
        fix: 'Use subprocess.run() with a list of arguments and shell=False instead of os.system().',
        cwe: 'CWE-78',
    },
    {
        id: 'PY-004',
        name: 'Python subprocess with shell=True',
        description:
            'Using subprocess with shell=True allows shell injection attacks.',
        severity: 'critical',
        category: 'python-specific',
        pattern: /subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/g,
        fix: 'Use subprocess with shell=False (default) and pass arguments as a list.',
        cwe: 'CWE-78',
    },
    {
        id: 'PY-005',
        name: 'Python Pickle Deserialization',
        description:
            'pickle.loads() can execute arbitrary code during deserialization of untrusted data.',
        severity: 'critical',
        category: 'python-specific',
        pattern: /pickle\.(?:loads?|Unpickler)\s*\(/g,
        fix: 'Never unpickle data from untrusted sources. Use JSON or other safe serialization formats.',
        cwe: 'CWE-502',
    },
    {
        id: 'PY-006',
        name: 'Python SQL String Formatting',
        description:
            'Using string formatting in SQL queries leads to SQL injection vulnerabilities.',
        severity: 'critical',
        category: 'python-specific',
        pattern: /(?:execute|executemany)\s*\(\s*(?:f["']|["'].*%s|["'].*\.format\(|["'].*\+)/g,
        fix: 'Use parameterized queries with placeholders: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        cwe: 'CWE-89',
    },
    {
        id: 'PY-007',
        name: 'Python YAML Unsafe Load',
        description:
            'yaml.load() without SafeLoader can execute arbitrary Python code.',
        severity: 'critical',
        category: 'python-specific',
        pattern: /yaml\.load\s*\([^)]*(?!Loader\s*=\s*(?:yaml\.)?SafeLoader|Loader\s*=\s*(?:yaml\.)?CSafeLoader)/g,
        fix: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).',
        cwe: 'CWE-502',
    },
    {
        id: 'PY-008',
        name: 'Python Hardcoded Secret',
        description:
            'Secrets hardcoded in Python source code can be extracted from bytecode or source.',
        severity: 'critical',
        category: 'python-specific',
        pattern: /(?:SECRET_KEY|DATABASE_PASSWORD|API_KEY|AWS_SECRET)\s*=\s*["'][^"']{8,}["']/g,
        fix: 'Use environment variables (os.environ) or a secrets manager for sensitive values.',
        cwe: 'CWE-798',
    },
    {
        id: 'PY-009',
        name: 'Python Debug Mode in Production',
        description:
            'Running Flask/Django with debug mode enabled in production exposes detailed error pages and allows code execution.',
        severity: 'high',
        category: 'python-specific',
        pattern: /(?:app\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)/g,
        fix: 'Set debug=False in production. Use environment variables to control debug mode.',
        cwe: 'CWE-489',
    },
    {
        id: 'PY-010',
        name: 'Python Weak Hash (MD5/SHA1)',
        description:
            'MD5 and SHA1 are cryptographically broken and should not be used for security.',
        severity: 'high',
        category: 'python-specific',
        pattern: /hashlib\.(?:md5|sha1)\s*\(/g,
        fix: 'Use hashlib.sha256() or hashlib.sha3_256() for hashing. Use bcrypt for passwords.',
        cwe: 'CWE-328',
    },
    {
        id: 'PY-011',
        name: 'Python Jinja2 No Auto-Escape',
        description:
            'Disabling auto-escaping in Jinja2 templates enables XSS attacks.',
        severity: 'high',
        category: 'python-specific',
        pattern: /Environment\s*\([^)]*autoescape\s*=\s*False/g,
        fix: 'Set autoescape=True in Jinja2 Environment or use select_autoescape().',
        cwe: 'CWE-79',
    },
    {
        id: 'PY-012',
        name: 'Python Temporary File Race Condition',
        description:
            'Using mktemp() creates a race condition. The file can be replaced between creation and use.',
        severity: 'medium',
        category: 'python-specific',
        pattern: /tempfile\.mktemp\s*\(/g,
        fix: 'Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() for secure temporary files.',
        cwe: 'CWE-377',
    },
    {
        id: 'PY-013',
        name: 'Python Assert in Production',
        description:
            'Assert statements are removed when Python runs with -O flag, bypassing security checks.',
        severity: 'medium',
        category: 'python-specific',
        pattern: /\bassert\s+(?:request|user|session|token|auth|permission)/g,
        fix: 'Use proper if statements with exceptions for security checks instead of assert.',
        cwe: 'CWE-617',
    },

    // ==================== PHP SPECIFIC ====================
    {
        id: 'PHP-001',
        name: 'PHP SQL Injection',
        description:
            'Concatenating user input into SQL queries in PHP leads to SQL injection.',
        severity: 'critical',
        category: 'php-specific',
        pattern: /(?:mysql_query|mysqli_query|pg_query|\$\w+->query)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP).*\$(?:_GET|_POST|_REQUEST|_COOKIE)/gi,
        fix: 'Use prepared statements with PDO or MySQLi: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
        cwe: 'CWE-89',
    },
    {
        id: 'PHP-002',
        name: 'PHP eval() Usage',
        description:
            'eval() in PHP executes arbitrary PHP code and is extremely dangerous.',
        severity: 'critical',
        category: 'php-specific',
        pattern: /\beval\s*\(\s*\$/g,
        fix: 'Never use eval() with user input. Restructure code to use proper PHP functions and classes.',
        cwe: 'CWE-94',
    },
    {
        id: 'PHP-003',
        name: 'PHP system/exec Command Injection',
        description:
            'PHP system(), exec(), passthru(), and shell_exec() can execute arbitrary commands.',
        severity: 'critical',
        category: 'php-specific',
        pattern: /(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$/g,
        fix: 'Use escapeshellarg() and escapeshellcmd() to sanitize input. Prefer specific PHP functions over shell commands.',
        cwe: 'CWE-78',
    },
    {
        id: 'PHP-004',
        name: 'PHP Unserialize Vulnerability',
        description:
            'unserialize() with untrusted data can lead to object injection and remote code execution.',
        severity: 'critical',
        category: 'php-specific',
        pattern: /\bunserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|input|data)/g,
        fix: 'Use json_decode() instead of unserialize() for data exchange. If unserialize is needed, use allowed_classes option.',
        cwe: 'CWE-502',
    },
    {
        id: 'PHP-005',
        name: 'PHP File Inclusion (LFI/RFI)',
        description:
            'Including files based on user input can lead to Local/Remote File Inclusion attacks.',
        severity: 'critical',
        category: 'php-specific',
        pattern: /(?:include|require|include_once|require_once)\s*\(\s*\$(?:_GET|_POST|_REQUEST|file|path|page|input)/g,
        fix: 'Never use user input in file inclusion paths. Use a whitelist of allowed files.',
        cwe: 'CWE-98',
    },
    {
        id: 'PHP-006',
        name: 'PHP extract() Usage',
        description:
            'extract() can overwrite existing variables including security-critical ones.',
        severity: 'high',
        category: 'php-specific',
        pattern: /\bextract\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|data|input)/g,
        fix: 'Avoid extract() with user data. Access array elements directly or use extract() with EXTR_SKIP flag.',
        cwe: 'CWE-621',
    },
    {
        id: 'PHP-007',
        name: 'PHP XSS via Echo',
        description:
            'Echoing user input without escaping leads to Cross-Site Scripting.',
        severity: 'high',
        category: 'php-specific',
        pattern: /(?:echo|print)\s+\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/g,
        fix: 'Always escape output with htmlspecialchars($input, ENT_QUOTES, "UTF-8").',
        cwe: 'CWE-79',
    },
    {
        id: 'PHP-008',
        name: 'PHP Weak Password Hashing',
        description:
            'Using md5() or sha1() for password hashing is insecure.',
        severity: 'high',
        category: 'php-specific',
        pattern: /(?:md5|sha1)\s*\(\s*\$(?:password|passwd|pass|pwd)/gi,
        fix: 'Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID for secure password hashing.',
        cwe: 'CWE-328',
    },
    {
        id: 'PHP-009',
        name: 'PHP Deprecated mysql_ Functions',
        description:
            'The mysql_ extension is removed since PHP 7.0 and has known security issues.',
        severity: 'high',
        category: 'php-specific',
        pattern: /\bmysql_(?:connect|query|fetch|select_db|real_escape_string)\s*\(/g,
        fix: 'Upgrade to PDO or MySQLi with prepared statements.',
        cwe: 'CWE-477',
    },
    {
        id: 'PHP-010',
        name: 'PHP Direct Superglobal in SQL',
        description:
            'Using $_GET, $_POST, or $_REQUEST directly in queries is a SQL injection vector.',
        severity: 'critical',
        category: 'php-specific',
        pattern: /["'](?:SELECT|INSERT|UPDATE|DELETE)\s+.*\$_(?:GET|POST|REQUEST)\s*\[/gi,
        fix: 'Always use prepared statements. Validate and sanitize all input before use.',
        cwe: 'CWE-89',
    },
    {
        id: 'PHP-011',
        name: 'PHP Exposed phpinfo()',
        description:
            'phpinfo() exposes server configuration details to attackers.',
        severity: 'medium',
        category: 'php-specific',
        pattern: /\bphpinfo\s*\(\s*\)/g,
        fix: 'Remove phpinfo() calls from production code. Use it only in restricted local development.',
        cwe: 'CWE-200',
    },

    // ==================== GO SPECIFIC ====================
    {
        id: 'GO-001',
        name: 'Go SQL Injection',
        description:
            'String concatenation or fmt.Sprintf in Go SQL queries leads to SQL injection.',
        severity: 'critical',
        category: 'go-specific',
        pattern: /(?:db\.(?:Query|Exec|QueryRow)|\.(?:Query|Exec|QueryRow))\s*\(\s*(?:fmt\.Sprintf|"[^"]*"\s*\+|\w+\s*\+\s*")/g,
        fix: 'Use parameterized queries with placeholders: db.Query("SELECT * FROM users WHERE id = $1", userID)',
        cwe: 'CWE-89',
    },
    {
        id: 'GO-002',
        name: 'Go os/exec Command Injection',
        description:
            'Using os/exec with unsanitized user input can lead to command injection.',
        severity: 'critical',
        category: 'go-specific',
        pattern: /exec\.Command\s*\(\s*(?:fmt\.Sprintf|[^")\s]+\s*\+|r\.(?:FormValue|URL\.Query))/g,
        fix: 'Validate and sanitize all user input before passing to exec.Command. Use a whitelist of allowed commands.',
        cwe: 'CWE-78',
    },
    {
        id: 'GO-003',
        name: 'Go Unescaped HTML Template',
        description:
            'Using text/template instead of html/template for web output enables XSS.',
        severity: 'high',
        category: 'go-specific',
        pattern: /["']text\/template["']/g,
        fix: 'Use "html/template" instead of "text/template" for rendering HTML to auto-escape user content.',
        cwe: 'CWE-79',
    },
    {
        id: 'GO-004',
        name: 'Go TLS InsecureSkipVerify',
        description:
            'Setting InsecureSkipVerify to true disables TLS certificate validation.',
        severity: 'critical',
        category: 'go-specific',
        pattern: /InsecureSkipVerify\s*:\s*true/g,
        fix: 'Remove InsecureSkipVerify: true. Configure proper TLS certificates for secure communication.',
        cwe: 'CWE-295',
    },
    {
        id: 'GO-005',
        name: 'Go Hardcoded Credentials',
        description:
            'Hardcoded credentials in Go source code are easily extractable from compiled binaries.',
        severity: 'critical',
        category: 'go-specific',
        pattern: /(?:password|apiKey|secret|token)\s*(?::=|=)\s*"[^"]{8,}"/g,
        fix: 'Use environment variables (os.Getenv) or a vault/secrets manager for credentials.',
        cwe: 'CWE-798',
    },
    {
        id: 'GO-006',
        name: 'Go Weak Random Number',
        description:
            'math/rand is not cryptographically secure and should not be used for security-sensitive operations.',
        severity: 'medium',
        category: 'go-specific',
        pattern: /["']math\/rand["']/g,
        fix: 'Use "crypto/rand" for cryptographically secure random number generation.',
        cwe: 'CWE-338',
    },
    {
        id: 'GO-007',
        name: 'Go Unhandled Error',
        description:
            'Ignoring errors in Go can hide security issues and lead to unexpected behavior.',
        severity: 'medium',
        category: 'go-specific',
        pattern: /\b\w+\s*,\s*_\s*(?::=|=)\s*(?:\w+\.(?:Query|Exec|Open|Read|Write|Dial|Listen|Get|Post))/g,
        fix: 'Always handle errors: if err != nil { return err }. Never silently discard errors.',
        cwe: 'CWE-391',
    },
    {
        id: 'GO-008',
        name: 'Go HTTP Without Timeout',
        description:
            'Creating HTTP servers or clients without timeouts can lead to denial of service.',
        severity: 'medium',
        category: 'go-specific',
        pattern: /http\.ListenAndServe\s*\(/g,
        fix: 'Use http.Server{} with ReadTimeout, WriteTimeout, and IdleTimeout configured.',
        cwe: 'CWE-400',
    },
    {
        id: 'GO-009',
        name: 'Go Path Traversal',
        description:
            'Using user input in file paths without sanitization enables path traversal attacks.',
        severity: 'high',
        category: 'go-specific',
        pattern: /(?:os\.Open|os\.ReadFile|ioutil\.ReadFile|os\.Create)\s*\(\s*(?:r\.(?:FormValue|URL\.Query)|fmt\.Sprintf|[^")]+\s*\+)/g,
        fix: 'Use filepath.Clean() and validate that the resolved path is within the expected directory.',
        cwe: 'CWE-22',
    },
    {
        id: 'GO-010',
        name: 'Go Goroutine Leak Risk',
        description:
            'Starting goroutines without proper lifecycle management can cause resource leaks.',
        severity: 'low',
        category: 'go-specific',
        pattern: /go\s+func\s*\(\s*\)\s*\{[^}]*for\s*\{/g,
        fix: 'Use context.Context for goroutine cancellation. Ensure all goroutines have exit conditions.',
        cwe: 'CWE-400',
    },

    // ==================== C/C++ SPECIFIC ====================
    {
        id: 'CPP-001',
        name: 'C/C++ gets() Usage',
        description:
            'gets() has no bounds checking and always causes a buffer overflow vulnerability.',
        severity: 'critical',
        category: 'cpp-specific',
        pattern: /\bgets\s*\(/g,
        fix: 'Use fgets() with a buffer size limit: fgets(buffer, sizeof(buffer), stdin)',
        cwe: 'CWE-120',
    },
    {
        id: 'CPP-002',
        name: 'C/C++ strcpy Buffer Overflow',
        description:
            'strcpy() does not check buffer bounds and can cause buffer overflows.',
        severity: 'critical',
        category: 'cpp-specific',
        pattern: /\bstrcpy\s*\(/g,
        fix: 'Use strncpy() or strlcpy() with proper size limits, or use std::string in C++.',
        cwe: 'CWE-120',
    },
    {
        id: 'CPP-003',
        name: 'C/C++ sprintf Buffer Overflow',
        description:
            'sprintf() does not check buffer bounds and can cause buffer overflows.',
        severity: 'critical',
        category: 'cpp-specific',
        pattern: /\bsprintf\s*\(/g,
        fix: 'Use snprintf() with proper buffer size limits.',
        cwe: 'CWE-120',
    },
    {
        id: 'CPP-004',
        name: 'C/C++ strcat Buffer Overflow',
        description:
            'strcat() does not check buffer bounds and can cause buffer overflows when concatenating strings.',
        severity: 'critical',
        category: 'cpp-specific',
        pattern: /\bstrcat\s*\(/g,
        fix: 'Use strncat() with proper size limits, or use std::string in C++.',
        cwe: 'CWE-120',
    },
    {
        id: 'CPP-005',
        name: 'C/C++ scanf Buffer Overflow',
        description:
            'scanf() with %s does not limit input size, causing buffer overflows.',
        severity: 'high',
        category: 'cpp-specific',
        pattern: /\bscanf\s*\(\s*["'][^"']*%s/g,
        fix: 'Use scanf with width specifier: scanf("%99s", buffer) or use fgets().',
        cwe: 'CWE-120',
    },
    {
        id: 'CPP-006',
        name: 'C/C++ Format String Vulnerability',
        description:
            'Passing user-controlled strings as format arguments enables format string attacks.',
        severity: 'critical',
        category: 'cpp-specific',
        pattern: /(?:printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*(?!.*["'])\w+\s*\)/g,
        fix: 'Always use a format string: printf("%s", user_input) instead of printf(user_input).',
        cwe: 'CWE-134',
    },
    {
        id: 'CPP-007',
        name: 'C/C++ malloc Without Null Check',
        description:
            'Using malloc() result without checking for NULL can cause null pointer dereference.',
        severity: 'high',
        category: 'cpp-specific',
        pattern: /\w+\s*=\s*(?:malloc|calloc|realloc)\s*\([^)]+\)\s*;(?!\s*if\s*\()/g,
        fix: 'Always check if malloc returns NULL: if (ptr == NULL) { handle_error(); }',
        cwe: 'CWE-476',
    },
    {
        id: 'CPP-008',
        name: 'C/C++ Use After Free Risk',
        description:
            'Using memory after free() leads to undefined behavior and potential code execution.',
        severity: 'critical',
        category: 'cpp-specific',
        pattern: /free\s*\(\s*(\w+)\s*\)\s*;(?!\s*\1\s*=\s*NULL)/g,
        fix: 'Set pointer to NULL after free: free(ptr); ptr = NULL; Or use smart pointers in C++.',
        cwe: 'CWE-416',
    },
    {
        id: 'CPP-009',
        name: 'C/C++ system() Command Injection',
        description:
            'system() passes commands to the shell, enabling command injection attacks.',
        severity: 'critical',
        category: 'cpp-specific',
        pattern: /\bsystem\s*\(\s*(?!["'])/g,
        fix: 'Avoid system(). Use exec family functions (execve, execvp) with proper argument lists.',
        cwe: 'CWE-78',
    },
    {
        id: 'CPP-010',
        name: 'C/C++ Integer Overflow Risk',
        description:
            'Arithmetic operations without overflow checking can lead to integer overflow vulnerabilities.',
        severity: 'medium',
        category: 'cpp-specific',
        pattern: /(?:int|short|long)\s+\w+\s*=\s*\w+\s*[*+]\s*\w+/g,
        fix: 'Check for overflow before arithmetic: if (a > INT_MAX - b) { error; } Or use safe integer libraries.',
        cwe: 'CWE-190',
    },
    {
        id: 'CPP-011',
        name: 'C/C++ Weak Random (rand)',
        description:
            'rand() and srand() produce predictable values and should not be used for security.',
        severity: 'medium',
        category: 'cpp-specific',
        pattern: /\b(?:srand|rand)\s*\(/g,
        fix: 'Use cryptographically secure alternatives: /dev/urandom, CryptGenRandom(), or std::random_device in C++.',
        cwe: 'CWE-338',
    },
];

