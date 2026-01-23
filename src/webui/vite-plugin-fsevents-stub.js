// Vite plugin to handle fsevents on non-macOS platforms
export function fseventsStubPlugin() {
  const stubFsevents = '\0stub-fsevents';
  
  return {
    name: 'fsevents-stub',
    enforce: 'pre',
    
    resolveId(id, importer) {
      if (id === 'fsevents') {
        return stubFsevents;
      }
      
      // Don't bundle server-side Node modules for the client build
      // If the importer is from a server-side module path, externalize all Node builtins
      if (importer && (
        importer.includes('/vite/dist/node/') || 
        importer.includes('/rollup/dist/es/') || 
        importer.includes('/fdir/dist/') ||
        importer.includes('/tinyglobby/dist/') ||
        importer.includes('/jiti/dist/') ||
        importer.includes('/@vitejs/plugin-react/dist/')
      )) {
        // Externalize Node.js built-ins
        if (id.startsWith('node:') || ['path', 'fs', 'os', 'util', 'stream', 'events', 'crypto', 'http', 'https', 'net', 'tls', 'zlib', 'buffer', 'url', 'tty', 'child_process', 'module', 'perf_hooks', 'process', 'v8', 'worker_threads', 'readline', 'dns', 'assert'].includes(id)) {
          return { id, external: true };
        }
        // Also externalize known server-side Node modules
        const serverModules = ['fdir', 'tinyglobby', 'chokidar', 'picomatch', 'fast-glob'];
        if (serverModules.some(mod => id.includes(mod))) {
          return { id, external: true };
        }
      }
    },
    
    load(id) {
      if (id === stubFsevents) {
        return `
          export default class FSEvents {};
          export class FSWatcher {};
        `;
      }
    }
  };
}
