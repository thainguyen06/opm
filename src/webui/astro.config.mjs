import react from '@astrojs/react';
import relativeLinks from './links';
import tailwind from '@astrojs/tailwind';
import { defineConfig } from 'astro/config';
import { fseventsStubPlugin } from './vite-plugin-fsevents-stub.js';

export default defineConfig({
	build: { 
		format: 'file', 
		assets: 'assets',
	},
	integrations: [tailwind(), react(), relativeLinks()],
	vite: {
		plugins: [fseventsStubPlugin()],
		build: {
			rollupOptions: {
				output: {
					assetFileNames: 'assets/[name].[hash][extname]',
					chunkFileNames: 'assets/[name].[hash].js',
					entryFileNames: 'assets/[name].[hash].js',
				}
			}
		}
	}
});
