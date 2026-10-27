// Generates the PWA icons in public/icons/ without any image tooling (plain zlib + PNG chunks).
// Run: node scripts/make-icons.js
import fs from 'node:fs';
import zlib from 'node:zlib';

const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
};

function icon(size) {
  const raw = Buffer.alloc((size * 3 + 1) * size);
  const bg = [0x1f, 0x6f, 0xeb];
  const fg = [0xff, 0xff, 0xff];
  const dot = [0xff, 0x5a, 0x4f];
  for (let y = 0; y < size; y++) {
    raw[y * (size * 3 + 1)] = 0;
    for (let x = 0; x < size; x++) {
      const u = (x + 0.5) / size;
      const v = (y + 0.5) / size;
      let px = bg;
      // Bell: dome + flared body + clapper, all inside the maskable safe zone.
      const dome = (u - 0.5) ** 2 + (v - 0.45) ** 2 < 0.2 ** 2 && v < 0.5;
      const body = v >= 0.45 && v < 0.64 && Math.abs(u - 0.5) < 0.2 + (v - 0.45) * 0.45;
      const clapper = (u - 0.5) ** 2 + (v - 0.69) ** 2 < 0.055 ** 2;
      if (dome || body || clapper) px = fg;
      if ((u - 0.66) ** 2 + (v - 0.32) ** 2 < 0.075 ** 2) px = dot;
      raw.set(px, y * (size * 3 + 1) + 1 + x * 3);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // RGB
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const dir = new URL('../public/icons/', import.meta.url);
fs.mkdirSync(dir, { recursive: true });
for (const [name, size] of [['icon-192.png', 192], ['icon-512.png', 512], ['apple-touch-icon.png', 180]]) {
  fs.writeFileSync(new URL(name, dir), icon(size));
}
