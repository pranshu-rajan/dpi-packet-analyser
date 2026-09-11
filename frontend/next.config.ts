import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: process.env.VERCEL ? undefined : process.env.DOCKER_BUILD === "1" ? "standalone" : undefined,
};

export default nextConfig;
