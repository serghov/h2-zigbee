// End-to-end check of the Home Assistant panel against a running Home Assistant with ZHA
// and one h2-zigbee switch: log in with a long-lived token, load a source onto the switch,
// read it back, reload the page, and take desktop and phone screenshots.
// It REPLACES the rule program on the first switch in the list: use a bench switch.
//   npm i puppeteer-core
//   node panel_flow.mjs <long-lived token> <source.c> <output dir> [http://127.0.0.1:8123]
import puppeteer from "puppeteer-core";
import fs from "node:fs";
const [token, srcFile, outdir, base = "http://127.0.0.1:8123"] = process.argv.slice(2);
const browser = await puppeteer.launch({ executablePath: "/usr/bin/chromium", headless: true, args: ["--no-first-run", "--no-sandbox", "--enable-unsafe-swiftshader"] });
const page = await browser.newPage();
await page.setViewport({ width: 1400, height: 850 });
page.on("response", (r) => { if (r.status() >= 400) console.log("HTTP", r.status(), r.url()); });
page.on("pageerror", (e) => console.log("pageerror", String(e).slice(0, 300)));
page.on("dialog", (d) => d.accept());
await page.goto(base + "/h2_rules_static/manifest.json");
await page.evaluate((token, base) => localStorage.setItem("hassTokens", JSON.stringify({ access_token: token, token_type: "Bearer", expires_in: 1e9, hassUrl: base, clientId: base + "/", expires: Date.now() + 1e12, refresh_token: "" })), token, base);
const open = async () => {
  await page.goto(base + "/h2-rules", { waitUntil: "networkidle2" });
  await new Promise((r) => setTimeout(r, 3000));
  const f = page.frames().find((x) => x !== page.mainFrame());
  await f.waitForFunction(() => { const b = document.querySelector('[data-act="upload"]'); return b && !b.disabled; }, { timeout: 120000 });
  return f;
};
let f = await open();
const text = (sel) => f.$eval(sel, (e) => e.textContent);
const msgIs = (re, ms = 120000) => f.waitForFunction((s) => new RegExp(s, "i").test(document.querySelector('[data-id="msg"]').textContent), { timeout: ms }, re.source);
await f.evaluate((src) => { document.querySelector("h2-rules-panel").editor.value = src; }, fs.readFileSync(srcFile, "utf8"));
let t0 = Date.now();
await f.click('[data-act="upload"]');
await msgIs(/Running on the switch|did not take|failed/);
console.log(`upload (${((Date.now() - t0) / 1000).toFixed(1)} s):`, await text('[data-id="msg"]'));
console.log("state:", await text('[data-id="state"]'));
t0 = Date.now();
await f.evaluate(() => document.querySelector('[data-act="readback"]').click());
await msgIs(/Read \d+ bytes|does not hand|stopped|match/);
console.log(`readback (${((Date.now() - t0) / 1000).toFixed(1)} s):`, await text('[data-id="msg"]'));
console.log((await text('[data-id="pane"]')).split("\n").slice(0, 9).join("\n"));
await page.screenshot({ path: outdir + "/shot2.png" });
// reload: the saved source comes back and matches the switch
f = await open();
console.log("after reload:", await text('[data-id="state"]'));
console.log("editor starts with:", (await f.evaluate(() => document.querySelector("h2-rules-panel").editor.value)).slice(0, 60).replace(/\n/g, " | "));
// phone
await page.setViewport({ width: 390, height: 780, isMobile: true, hasTouch: true });
f = await open();
await page.screenshot({ path: outdir + "/shot3.png" });
await f.evaluate(() => document.querySelector('[data-tab="log"]').click());
await page.screenshot({ path: outdir + "/shot4.png" });
await browser.close();
