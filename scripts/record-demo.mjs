// Records the scripted demo to video using Playwright (already a repo dependency).
// Run: npm run deception-lab:record  [-- --width 1920 --height 1080]
// Output: deception-lab/recordings/gatra-deception-lab-demo.webm (+ .mp4 if ffmpeg is on PATH)
import { spawnSync } from 'node:child_process';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { LAB_ROOT, guardNetwork, launchBrowser, startServer } from './browser.mjs';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? Number(process.argv[i + 1]) : fallback;
};
const width = arg('width', 1920);
const height = arg('height', 1080);
const outDir = join(LAB_ROOT, 'recordings');
const tmpDir = join(outDir, '.tmp');
await mkdir(tmpDir, { recursive: true });

const { server, url } = await startServer();
const browser = await launchBrowser({ headedFallback: true });
const violations = [];
let ok = false;
try {
  const context = await browser.newContext({
    viewport: { width, height },
    recordVideo: { dir: tmpDir, size: { width, height } },
  });
  const page = await context.newPage();
  guardNetwork(page, violations);
  const started = Date.now();
  await page.goto(`${url}?demo=1`);
  // Poll the director and log when each shot starts (for docs/STORYBOARD.md).
  const timecodes = [];
  let lastShot = 0;
  for (;;) {
    const d = await page.evaluate(() => window.__demo);
    if (d?.shot && d.shot !== lastShot) {
      lastShot = d.shot;
      const sec = (Date.now() - started) / 1000;
      timecodes.push(`shot ${d.shot}/${d.totalShots} starts at ${Math.floor(sec / 60)}:${String(Math.floor(sec % 60)).padStart(2, '0')}`);
    }
    if (d?.status === 'done') break;
    if (d?.status === 'stopped' || Date.now() - started > 8 * 60_000) throw new Error(`demo did not finish (status ${d?.status})`);
    await page.waitForTimeout(250);
  }
  const seconds = Math.round((Date.now() - started) / 1000);
  await writeFile(join(outDir, 'timecodes.txt'), `${timecodes.join('\n')}\nend at ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}\n`);
  console.log(timecodes.join('\n'));
  await page.waitForTimeout(1500);
  const video = page.video();
  await context.close();
  const webm = join(outDir, 'gatra-deception-lab-demo.webm');
  await rename(await video.path(), webm);
  console.log(`Recorded ${seconds}s of demo → ${webm}`);
  if (spawnSync('ffmpeg', ['-version']).status === 0) {
    const mp4 = webm.replace(/\.webm$/, '.mp4');
    const r = spawnSync('ffmpeg', ['-y', '-loglevel', 'error', '-i', webm, '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '20', mp4]);
    console.log(r.status === 0 ? `Converted → ${mp4}` : 'ffmpeg conversion failed; the .webm is still usable.');
  } else {
    console.log('ffmpeg not found on PATH; keeping .webm only.');
  }
  if (violations.length) throw new Error(`Non-loopback requests during recording: ${violations.join(', ')}`);
  ok = true;
} finally {
  await browser.close();
  await server.close();
  await rm(tmpDir, { recursive: true, force: true });
}
process.exit(ok ? 0 : 1);
