import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
    title: 'SecureScan — React & Next.js Security Scanner',
    description:
        'Scan your React and Next.js code for security vulnerabilities, XSS, injection flaws, and misconfigurations. Get detailed reports with fix recommendations.',
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
