// /MY-VITE-APP/vite.config.js
import { defineConfig } from 'vite';

export default defineConfig({
    build: {
        minify: 'terser',
        terserOptions: {
            mangle: {
                properties: true
            },
        }
    },
});