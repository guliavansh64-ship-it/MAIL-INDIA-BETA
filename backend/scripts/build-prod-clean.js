'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { execSync } = require('node:child_process');

const MAILBRIDGE_DIR = path.resolve(__dirname, '../../');
const WORKSPACE_DIR = path.resolve(MAILBRIDGE_DIR, '../');
const DIST_DIR = path.join(MAILBRIDGE_DIR, 'dist');
const CLEAN_FRONTEND = path.join(DIST_DIR, 'clean-frontend');
const CLEAN_BACKEND = path.join(DIST_DIR, 'clean-backend');

console.log('====================================================');
console.log('📦 MAIL INDIA - UNENCRYPTED ROOT-LEVEL ZIP PACKAGER');
console.log('====================================================');

// 1. Prepare clean dist directories
if (fs.existsSync(CLEAN_FRONTEND)) fs.rmSync(CLEAN_FRONTEND, { recursive: true, force: true });
if (fs.existsSync(CLEAN_BACKEND)) fs.rmSync(CLEAN_BACKEND, { recursive: true, force: true });
fs.mkdirSync(CLEAN_FRONTEND, { recursive: true });
fs.mkdirSync(CLEAN_BACKEND, { recursive: true });

function copyRecursive(src, dest) {
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    for (const file of fs.readdirSync(src)) {
      copyRecursive(path.join(src, file), path.join(dest, file));
    }
  } else {
    fs.copyFileSync(src, dest);
  }
}

// 2. Copy Frontend Files directly to root of CLEAN_FRONTEND
console.log('📄 Packaging Clean Frontend Client...');
const frontendSrc = path.join(MAILBRIDGE_DIR, 'frontend');
for (const file of fs.readdirSync(frontendSrc)) {
  copyRecursive(path.join(frontendSrc, file), path.join(CLEAN_FRONTEND, file));
}

// 3. Copy Backend Files directly to CLEAN_BACKEND
console.log('📄 Packaging Clean Backend...');
copyRecursive(path.join(MAILBRIDGE_DIR, 'backend'), path.join(CLEAN_BACKEND, 'backend'));
copyRecursive(path.join(MAILBRIDGE_DIR, 'api'), path.join(CLEAN_BACKEND, 'api'));

const backendFiles = [
  'package.json',
  'package-lock.json',
  '.env.example',
  'database.rules.json',
  'README.md',
  'vercel.json'
];

for (const f of backendFiles) {
  const p = path.join(MAILBRIDGE_DIR, f);
  if (fs.existsSync(p)) fs.copyFileSync(p, path.join(CLEAN_BACKEND, f));
}

// 4. Generate Clean ZIP packages with root-level files (NO extra enclosing subfolders)
console.log('🗜  Compressing Root-Level ZIP Archives...');

const frontendZip = path.join(WORKSPACE_DIR, 'mailbridge-frontend.zip');
const backendZip = path.join(WORKSPACE_DIR, 'mailbridge-backend.zip');

function zipDirectory(sourceDir, targetZip) {
  if (fs.existsSync(targetZip)) fs.unlinkSync(targetZip);
  try {
    execSync(`cd "${sourceDir}" && zip -r -q "${targetZip}" .`, { stdio: 'pipe' });
  } catch {
    execSync(`powershell -NoProfile -Command "Compress-Archive -Path '${sourceDir}\\*' -DestinationPath '${targetZip}' -Force"`, { stdio: 'inherit' });
  }
}

zipDirectory(CLEAN_FRONTEND, frontendZip);
zipDirectory(CLEAN_BACKEND, backendZip);

// Also create aliases
fs.copyFileSync(frontendZip, path.join(WORKSPACE_DIR, 'mailbridge-frontend-unencrypted.zip'));
fs.copyFileSync(frontendZip, path.join(DIST_DIR, 'mailbridge-frontend.zip'));
fs.copyFileSync(backendZip, path.join(DIST_DIR, 'mailbridge-backend.zip'));

const fStats = fs.statSync(frontendZip);
const bStats = fs.statSync(backendZip);

console.log('====================================================');
console.log('✅ PACKAGING COMPLETE (UNENCRYPTED ROOT-LEVEL)');
console.log('====================================================');
console.log(`🌐 Frontend Clean ZIP : ${frontendZip} (${(fStats.size / 1024).toFixed(1)} KB)`);
console.log(`⚙️  Backend Clean ZIP  : ${backendZip} (${(bStats.size / 1024).toFixed(1)} KB)`);
console.log('👉 Unzipping will extract files directly into destination directory without extra subfolders.');
console.log('====================================================');
