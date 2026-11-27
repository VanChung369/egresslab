import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const moduleDir = fileURLToPath(new URL('../../../services/controller/', import.meta.url));
const outputDir = fileURLToPath(new URL('../src-tauri/binaries/', import.meta.url));

// Tauri names the target it builds for its hooks; a standalone run builds for the Rust host.
const triple =
  process.env.TAURI_ENV_TARGET_TRIPLE ||
  execFileSync('rustc', ['-vV'], { encoding: 'utf8' })
    .match(/^host: (.+)$/m)?.[1]
    ?.trim();

if (!triple) {
  throw new Error('Could not determine Rust target triple');
}

mkdirSync(outputDir, { recursive: true });

const build = (goos, goarch, output) =>
  execFileSync('go', ['build', '-trimpath', '-o', output, './cmd/egresslab-controller'], {
    cwd: moduleDir,
    env: { ...process.env, GOOS: goos, GOARCH: goarch, CGO_ENABLED: '0' },
    stdio: 'inherit'
  });

// A universal macOS app needs one sidecar holding both architectures, and Tauri builds the Rust
// app once per architecture, each needing its own sidecar too.
if (triple === 'universal-apple-darwin') {
  const arm64 = join(outputDir, 'egresslab-controller-aarch64-apple-darwin');
  const amd64 = join(outputDir, 'egresslab-controller-x86_64-apple-darwin');
  const binary = join(outputDir, `egresslab-controller-${triple}`);

  build('darwin', 'arm64', arm64);
  build('darwin', 'amd64', amd64);
  execFileSync('lipo', ['-create', '-output', binary, arm64, amd64]);

  console.log(`Controller sidecars built: ${arm64}, ${amd64}, ${binary}`);
  process.exit(0);
}

const goos = triple.includes('-apple-darwin')
  ? 'darwin'
  : triple.includes('-windows-')
    ? 'windows'
    : triple.includes('-linux-')
      ? 'linux'
      : undefined;

const goarch = triple.startsWith('x86_64-')
  ? 'amd64'
  : triple.startsWith('aarch64-')
    ? 'arm64'
    : undefined;

if (!goos || !goarch) {
  throw new Error(`Unsupported target: ${triple}`);
}

const extension = goos === 'windows' ? '.exe' : '';
const binary = join(outputDir, `egresslab-controller-${triple}${extension}`);

build(goos, goarch, binary);

console.log(`Controller sidecar built: ${binary}`);
