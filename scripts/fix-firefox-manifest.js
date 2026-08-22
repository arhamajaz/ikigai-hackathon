import fs from 'fs';
import path from 'path';

const manifestPath = path.resolve('dist/manifest.json');

if (fs.existsSync(manifestPath)) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  
  if (manifest.background) {
    const swFile = manifest.background.service_worker || 'service-worker-loader.js';
    manifest.background.scripts = [swFile];
  }

  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  console.log('✓ [SentinelEdge] Patched dist/manifest.json with background.scripts for Firefox compatibility.');
}
