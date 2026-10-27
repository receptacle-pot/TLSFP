const fs = require('fs');
const path = require('path');

const distDir = path.resolve(__dirname, 'dist');
const siteDir = fs.existsSync(path.resolve(__dirname, '../site'))
  ? path.resolve(__dirname, '../site')
  : fs.existsSync(path.resolve(__dirname, 'public'))
  ? path.resolve(__dirname, 'public')
  : path.resolve(__dirname, '../public');

console.log(`[build] Copying production assets from ${siteDir} to ${distDir}...`);

if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

fs.cpSync(siteDir, distDir, { recursive: true });

console.log('[build] Production website build ready.');
