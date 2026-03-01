import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
    title: 'SecureScan — Multi-Language Code Security Scanner',
    description:
        'Scan your JavaScript, Python, PHP, Go, and C/C++ code for security vulnerabilities. Detect XSS, injection flaws, buffer overflows, hardcoded secrets, and more. 89+ security rules. 100% client-side.',
    icons: {
        icon: '/WebAppScanner/icon.svg',
    },
    authors: [{ name: 'Muhammad Rajib Hawlader', url: 'https://rajib.uk' }],
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en">
            <body>{children}</body>
        </html>
    );
}
