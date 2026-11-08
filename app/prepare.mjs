import { cp, mkdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const root = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(root, 'dist');
await rm(dist, { recursive: true, force: true });
await mkdir(dist);
await cp(path.join(root, 'src'), dist, { recursive: true });
for (const dir of ['style', 'loader']) {
  await cp(path.join(root, '..', 'design', dir), path.join(dist, 'design', dir), { recursive: true });
}
