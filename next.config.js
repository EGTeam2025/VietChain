/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/docs/:path*',
        destination: '/:path*', // ánh xạ URL docs/... về file thực tế
      },
    ];
  },
};

const withNextra = require("nextra")({
  theme: "nextra-theme-docs",
  themeConfig: "./theme.config.jsx",
});

module.exports = withNextra(nextConfig);
