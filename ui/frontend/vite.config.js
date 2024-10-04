import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue2';

export default defineConfig({
    plugins: [vue()],
    server: {
        port: 8080,
        proxy: {
            '/api': {
                target: 'http://localhost:8090',
                changeOrigin: true,
                secure: false,
                ws: true,
            },
        },
    },
});
