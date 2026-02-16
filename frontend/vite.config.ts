/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/setupTests.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    globals: true,
  },
  // Use relative paths so assets work when served from embedded server
  base: './',
  build: {
    // Output to dist/ which will be embedded in the binary
    outDir: 'dist',
    // Generate assets with content hashes for caching
    assetsDir: 'assets',
    // Ensure source maps are not included in production
    sourcemap: false,
    // Minify for smaller binary size
    minify: 'esbuild',
    // Rollup options for better chunking
    rollupOptions: {
      output: {
        // Keep asset file names predictable for MIME type detection
        assetFileNames: 'assets/[name]-[hash][extname]',
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
      },
    },
  },
})
