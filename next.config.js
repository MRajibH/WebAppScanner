/** @type {import('next').NextConfig} */
const nextConfig = {
    output: 'export',
    reactStrictMode: true,
    basePath: '/WebAppScanner',
    assetPrefix: '/WebAppScanner/',
    images: {
        unoptimized: true,
    },
};

module.exports = nextConfig;
