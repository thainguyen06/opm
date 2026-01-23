/**
 * Vite plugin to prevent Node.js built-ins from being externalized during SSR bundling
 * This fixes the issue where Vite tries to make server-side dependencies browser-compatible
 */
export default function nodeBuiltinsPlugin() {
	return {
		name: 'node-builtins-ssr',
		enforce: 'pre',
		resolveId(id) {
			// Stub out fsevents (macOS-only optional dependency)
			if (id === 'fsevents') {
				return '\0fsevents-stub';
			}
			return null;
		},
		load(id) {
			// Provide an empty stub for the virtual fsevents module
			if (id === '\0fsevents-stub') {
				return 'export default {}';
			}
			return null;
		},
		config(config, { command }) {
			// Only apply during build, not dev
			if (command === 'build') {
				return {
					ssr: {
						// Prevent Node.js built-ins from being marked as external
						noExternal: true,
					},
					resolve: {
						// Don't apply browser field resolution for SSR code
						browserField: false,
					},
				};
			}
		},
	};
}
