import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The build writes into the Go package that embeds it, so `make ui` followed
// by `go build` produces a binary with the page inside.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../pkg/ui/dist',
    // Wipes the directory, which would take with it the .gitkeep that lets
    // `go build` succeed before the UI has ever been built. public/.gitkeep
    // is copied back in on every build, which is why that file exists.
    emptyOutDir: true,
  },
  server: {
    // `make dev.ui` runs this against a guard started separately, so the page
    // hot-reloads while talking to a real analyzer.
    proxy: {
      '/api': 'http://127.0.0.1:8080',
    },
  },
})
