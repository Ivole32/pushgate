// Static PWA files. The file set is read once at startup into memory; request paths are only
// looked up in that map, so there is no filesystem access derived from user input.
import fs from 'node:fs';
import path from 'node:path';

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.png': 'image/png',
};

// Hidden files and directories, installed packages and symbolic links are never published: a
// plugin's web directory may sit inside its package next to server code and configuration.
const SKIP = (entry) => entry.name.startsWith('.') || entry.name === 'node_modules' || entry.isSymbolicLink();

export function loadStatic(dir) {
  const files = new Map();
  const walk = (sub) => {
    for (const entry of fs.readdirSync(path.join(dir, sub), { withFileTypes: true })) {
      if (SKIP(entry)) continue;
      const rel = sub ? `${sub}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(rel);
      else if (TYPES[path.extname(entry.name)]) {
        files.set('/' + rel, { body: fs.readFileSync(path.join(dir, rel)), type: TYPES[path.extname(entry.name)] });
      }
    }
  };
  walk('');
  files.set('/', files.get('/index.html'));
  return files;
}

export function serveStatic(files, req, res, pathname) {
  const file = files.get(pathname);
  if (!file) return false;
  // The service worker and the page must update promptly; icons may be cached briefly.
  const cache = file.type.startsWith('image/') ? 'public, max-age=86400' : 'no-cache';
  res.writeHead(200, { 'Content-Type': file.type, 'Content-Length': file.body.length, 'Cache-Control': cache });
  res.end(req.method === 'HEAD' ? undefined : file.body);
  return true;
}
