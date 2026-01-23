import type { AstroIntegration, AstroConfig } from 'astro';
import { writeFileSync, readFileSync, readdirSync, statSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

export function leadingTrailingSlash(base?: string) {
	return base?.replace(/^\/*([^\/]+)(.*)([^\/]+)\/*$/, '/$1$2$3/') || '/';
}

export function replaceHTML({ outDirPath, filePath, base, html }: { outDirPath: string; filePath: string; base: string; html: string }) {
	const pattern = new RegExp(
		`(?<=<[^>]+\\s((href|src(set)?|poster|content|component-url|renderer-url)=["']?([^"']*,)?|style=("[^"]*|'[^']*|[^\\s]*)url\\(\\s*?["']?)\\s*?)${base}(?!\/)`,
		'gm'
	);

	const relativePath = path.relative(path.dirname(filePath), outDirPath).split(path.sep).join(path.posix.sep) || '{{base_path | safe}}';

	return html.replace(pattern, `${relativePath}/`);
}

export function replaceCSS({ outDirPath, filePath, base, css }: { outDirPath: string; filePath: string; base: string; css: string }) {
	const pattern = new RegExp(`(?<=url\\(\\s*?["']?\\s*?)${base}(?!\/)`, 'gm');

	const relativePath = path.relative(path.dirname(filePath), outDirPath).split(path.sep).join(path.posix.sep) || '{{base_path | safe}}';

	return css.replace(pattern, `${relativePath}/`);
}

// Recursive function to find files with a specific extension
function findFilesRecursive(dir: string, extension: string, fileList: string[] = []): string[] {
	const files = readdirSync(dir);

	files.forEach((file) => {
		const filePath = path.join(dir, file);
		const stat = statSync(filePath);

		if (stat.isDirectory()) {
			findFilesRecursive(filePath, extension, fileList);
		} else if (file.endsWith(extension)) {
			fileList.push(filePath);
		}
	});

	return fileList;
}

function relativeLinks({ config }: { config?: AstroConfig }): AstroIntegration {
	const base = leadingTrailingSlash(config?.base);

	return {
		name: 'relative-links',
		hooks: {
			'astro:build:done': async ({ dir }) => {
				const outDirPath = fileURLToPath(dir);

				try {
					const htmlFiles = findFilesRecursive(outDirPath, '.html');
					htmlFiles.forEach((filePath) => {
						writeFileSync(
							filePath,
							replaceHTML({
								outDirPath,
								filePath,
								base,
								html: readFileSync(filePath, 'utf8'),
							}),
							'utf8'
						);
					});

					const cssFiles = findFilesRecursive(outDirPath, '.css');
					cssFiles.forEach((filePath) => {
						writeFileSync(
							filePath,
							replaceCSS({
								outDirPath,
								filePath,
								base,
								css: readFileSync(filePath, 'utf8'),
							}),
							'utf8'
						);
					});
				} catch (error) {
					console.log(error);
				}
			},
		},
	};
}

export default function (): AstroIntegration {
	return {
		name: 'relative-links',
		hooks: {
			'astro:config:setup': ({ config, updateConfig }) => {
				updateConfig({
					integrations: [relativeLinks({ config })],
				});
			},
		},
	};
}
