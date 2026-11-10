'use strict';
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { execSync } = require('node:child_process');

const MAILBRIDGE_DIR = path.resolve(__dirname, '../../');
const WORKSPACE_DIR = path.resolve(MAILBRIDGE_DIR, '../');
const DIST_DIR = path.join(MAILBRIDGE_DIR, 'dist');
const DIST_BACKEND = path.join(DIST_DIR, 'backend');
const DIST_FRONTEND = path.join(DIST_DIR, 'frontend');

console.log('====================================================');
console.log('🚀 MAIL INDIA ENTERPRISE - CODE ENCRYPTION & BUILD');
console.log('====================================================');

// 1. Prepare clean dist directories
if (fs.existsSync(DIST_DIR)) fs.rmSync(DIST_DIR, { recursive: true, force: true });
fs.mkdirSync(DIST_BACKEND, { recursive: true });
fs.mkdirSync(DIST_FRONTEND, { recursive: true });

// 2. Encryption Keys
const BACKEND_KEY = [0x4d, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x64, 0x69, 0x61, 0x32, 0x30, 0x32, 0x36];
const FRONTEND_KEY = [170, 85, 204, 51, 153, 102, 12, 240, 15, 255];

function encryptBackendJs(sourceCode) {
  const compressed = zlib.deflateSync(sourceCode);
  const xored = Buffer.alloc(compressed.length);
  for (let i = 0; i < compressed.length; i++) {
    xored[i] = compressed[i] ^ BACKEND_KEY[i % BACKEND_KEY.length];
  }
  const b64 = xored.toString('base64');
  return `'use strict';
/**
 * MAIL INDIA ENTERPRISE - ENCRYPTED RUNTIME MODULE
 * (C) 2026 Mail India Cloud Platform. All rights reserved.
 * This file is encrypted and compiled for production deployment.
 */
const _0x4d = (function() {
  const _0xk = [0x4d, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x64, 0x69, 0x61, 0x32, 0x30, 0x32, 0x36];
  const _0xd = Buffer.from('${b64}', 'base64');
  const _0xb = Buffer.alloc(_0xd.length);
  for (let i = 0; i < _0xd.length; i++) _0xb[i] = _0xd[i] ^ _0xk[i % _0xk.length];
  return require('zlib').inflateSync(_0xb).toString('utf8');
})();
(new Function('exports', 'require', 'module', '__filename', '__dirname', _0x4d))(exports, require, module, __filename, __dirname);
`;
}

function encryptFrontendJs(sourceCode) {
  let enc = '';
  for (let i = 0; i < sourceCode.length; i++) {
    enc += String.fromCharCode(sourceCode.charCodeAt(i) ^ FRONTEND_KEY[i % FRONTEND_KEY.length]);
  }
  const b64 = Buffer.from(enc, 'binary').toString('base64');
  return `(function(){
  /**
   * MAIL INDIA WEB WORKSPACE - ENCRYPTED CLIENT ASSET
   * (C) 2026 Mail India Cloud Platform. All rights reserved.
   * Unauthorized decompilation, reverse engineering, or redistribution is strictly prohibited.
   */
  var _0xk = [170, 85, 204, 51, 153, 102, 12, 240, 15, 255];
  var _0xb = (typeof atob === 'function' ? atob : function(b) { return Buffer.from(b, 'base64').toString('binary'); })('${b64}');
  var _0xo = '';
  for (var i = 0; i < _0xb.length; i++) {
    _0xo += String.fromCharCode(_0xb.charCodeAt(i) ^ _0xk[i % _0xk.length]);
  }
  (1, eval)(_0xo);
})();
`;
}

function copyRecursive(src, dest, transformFn = null) {
  const stats = fs.statSync(src);
  if (stats.isDirectory()) {
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    for (const child of fs.readdirSync(src)) {
      if (child === 'node_modules' || child === '.git' || child === 'dist') continue;
      copyRecursive(path.join(src, child), path.join(dest, child), transformFn);
    }
  } else {
    const parent = path.dirname(dest);
    if (!fs.existsSync(parent)) fs.mkdirSync(parent, { recursive: true });
    if (transformFn) {
      const transformed = transformFn(src);
      if (transformed !== null) {
        fs.writeFileSync(dest, transformed);
        return;
      }
    }
    fs.copyFileSync(src, dest);
  }
}

// ==========================================
// 3. Process & Encrypt Backend
// ==========================================
console.log('📦 Encrypting Backend Source Code...');
const backendSrcDir = path.join(MAILBRIDGE_DIR, 'backend');

copyRecursive(backendSrcDir, path.join(DIST_BACKEND, 'backend'), srcFile => {
  if (srcFile.endsWith('.js') && !srcFile.includes('/test/')) {
    const code = fs.readFileSync(srcFile, 'utf8');
    return encryptBackendJs(code);
  }
  return null;
});

// Copy root configuration files to backend package
const backendExtras = [
  'package.json',
  'package-lock.json',
  '.env.example',
  'database.rules.json',
  'README.md',
  'vercel.json'
];

for (const extra of backendExtras) {
  const fPath = path.join(MAILBRIDGE_DIR, extra);
  if (fs.existsSync(fPath)) {
    fs.copyFileSync(fPath, path.join(DIST_BACKEND, extra));
  }
}

// Copy Vercel serverless entrypoint if present
const apiSrc = path.join(MAILBRIDGE_DIR, 'api');
if (fs.existsSync(apiSrc)) {
  const distApi = path.join(DIST_BACKEND, 'api');
  fs.mkdirSync(distApi, { recursive: true });
  fs.copyFileSync(path.join(apiSrc, 'index.js'), path.join(distApi, 'index.js'));
}

// Add startup runner script inside dist/backend
fs.writeFileSync(
  path.join(DIST_BACKEND, 'start.js'),
  `'use strict';
require('./backend/src/server.js');
`
);

console.log('✓ Backend files encrypted successfully.');

// ==========================================
// 4. Process & Encrypt Frontend
// ==========================================
console.log('🎨 Encrypting Frontend Client Code...');
const frontendSrcDir = path.join(MAILBRIDGE_DIR, 'frontend');

copyRecursive(frontendSrcDir, DIST_FRONTEND, srcFile => {
  if (srcFile.endsWith('.js')) {
    const code = fs.readFileSync(srcFile, 'utf8');
    return encryptFrontendJs(code);
  } else if (srcFile.endsWith('.html')) {
    let html = fs.readFileSync(srcFile, 'utf8');
    // Obfuscate inline script blocks
    html = html.replace(/<script(?![^>]*src=)([^>]*)>([\s\S]*?)<\/script>/gi, (match, attrs, body) => {
      const trimmed = body.trim();
      if (!trimmed || trimmed.length < 15) return match;
      const enc = encryptFrontendJs(trimmed);
      return `<script${attrs}>\n${enc}\n</script>`;
    });
    return html;
  }
  return null;
});

console.log('✓ Frontend files encrypted successfully.');

// ==========================================
// 5. Create Standalone ZIP Packages
// ==========================================
console.log('🗜  Generating Encrypted ZIP Packages...');

const backendZipWorkspace = path.join(WORKSPACE_DIR, 'mailbridge-backend-encrypted.zip');
const frontendZipWorkspace = path.join(WORKSPACE_DIR, 'mailbridge-frontend-encrypted.zip');
const backendZipDist = path.join(DIST_DIR, 'mailbridge-backend-encrypted.zip');
const frontendZipDist = path.join(DIST_DIR, 'mailbridge-frontend-encrypted.zip');

// Remove old zip files if present
[backendZipWorkspace, frontendZipWorkspace, backendZipDist, frontendZipDist].forEach(f => {
  if (fs.existsSync(f)) fs.unlinkSync(f);
});

// Create Backend ZIP
execSync(`cd "${DIST_BACKEND}" && zip -r -q "${backendZipWorkspace}" .`, { stdio: 'inherit' });
fs.copyFileSync(backendZipWorkspace, backendZipDist);

// Create Frontend ZIP
execSync(`cd "${DIST_FRONTEND}" && zip -r -q "${frontendZipWorkspace}" .`, { stdio: 'inherit' });
fs.copyFileSync(frontendZipWorkspace, frontendZipDist);

// Verify ZIP files
execSync(`zip -T "${backendZipWorkspace}"`, { stdio: 'pipe' });
execSync(`zip -T "${frontendZipWorkspace}"`, { stdio: 'pipe' });

const bStats = fs.statSync(backendZipWorkspace);
const fStats = fs.statSync(frontendZipWorkspace);

console.log('====================================================');
console.log('✨ ENCRYPTION & BUILD COMPLETED SUCCESSFULLY!');
console.log('====================================================');
console.log(`🔒 Backend Encrypted ZIP : ${backendZipWorkspace} (${(bStats.size / 1024).toFixed(1)} KB)`);
console.log(`🔒 Frontend Encrypted ZIP: ${frontendZipWorkspace} (${(fStats.size / 1024).toFixed(1)} KB)`);
console.log(`📁 Distribution Directory: ${DIST_DIR}`);
console.log('====================================================');
