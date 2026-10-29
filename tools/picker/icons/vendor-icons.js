// Builds icon/vendors/* and ki-vendor-icons.js from @lobehub/icons-static-svg (MIT)
// plus Hugging Face org avatars. Run vendor-avatars.js first to fetch them into %TEMP%\kiicons.
const fs = require("fs");
const path = require("path");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const src = path.join(process.env.TEMP, "kiicons");
const out = path.join(__dirname, "..", "..", "..", "icon", "vendors");

const lobe = {
  openai: "openai", google: "google-color", gemini: "gemini-color", qwen: "qwen-color", anthropic: "claude-color", claude: "claude-color",
  mistral: "mistral-color", mistralai: "mistral-color", zai: "zai", zhipu: "zhipu-color", deepseek: "deepseek-color",
  meta: "meta-color", metallama: "meta-color", nvidia: "nvidia-color", minimax: "minimax-color", moonshotai: "moonshot", moonshot: "moonshot",
  kimi: "moonshot", spacexai: "xai", xai: "xai", tencent: "tencent-color", aionlabs: "aionlabs-color", cohere: "cohere-color",
  bytedanceseed: "bytedance-color", bytedance: "bytedance-color", xiaomi: "xiaomimimo", openrouter: "openrouter-color", amazon: "aws-color",
  perplexity: "perplexity-color", sakana: "sakana-color", poolside: "poolside-color", inception: "inception", stepfun: "stepfun-color",
  upstage: "upstage-color", nous: "nousresearch", nousresearch: "nousresearch", liquid: "liquid", liquidai: "liquid",
  perceptron: "perceptron", ibm: "ibm", ibmgranite: "ibm", rekaai: "reka", reka: "reka", relace: "relace", morph: "morph-color",
  fireworks: "fireworks-color", dotsstudio: "dotsstudio", meituan: "longcat-color", arcee: "arcee-color", arceeai: "arcee-color",
  venice: "venice-color", cognitivecomputations: "venice-color", microsoft: "microsoft-color",
};
const avatars = {
  thinkingmachines: "thinkingmachines", inclusionai: "inclusionai", moondream: "moondream", thedrummer: "thedrummer", sao10k: "sao10k",
  nexagi: "nexagi", anthracite: "anthracite", anthraciteorg: "anthracite", gryphe: "gryphe", writer: "writer", elorian: "elorian", xingchen: "xingchen", xingchenagi: "xingchen", scaledown: "scaledown",
  inferencenet: "inferencenet", typesafe: "typesafe", reflection: "reflection",
};

(async () => {
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(out, { recursive: true });
  const map = {};
  for (const [k, f] of Object.entries(lobe)) {
    const svg = fs.readFileSync(path.join(src, "package/icons", f + ".svg"), "utf8").replace(/<title>[^<]*<\/title>/, "").replace(/ style="[^"]*"/, "");
    fs.writeFileSync(path.join(out, f + ".svg"), svg);
    map[k] = { f: f + ".svg", mono: /fill="currentColor"/.test(svg.slice(0, 200)) };
  }
  const browser = await chromium.launch({ executablePath: require("../../chromium-path.cjs") });
  const page = await browser.newPage();
  for (const [k, f] of Object.entries(avatars)) {
    const file = fs.readdirSync(path.join(src, "avatars")).find((x) => x.startsWith(f + "."));
    if (!file) continue;
    const b64 = fs.readFileSync(path.join(src, "avatars", file)).toString("base64");
    const mime = file.endsWith(".svg") ? "image/svg+xml" : file.endsWith(".png") ? "image/png" : file.endsWith(".webp") ? "image/webp" : "image/jpeg";
    if (!fs.existsSync(path.join(out, f + ".png"))) {
      const png = await page.evaluate(async ({ b64, mime }) => {
        const img = new Image();
        img.src = `data:${mime};base64,${b64}`;
        await img.decode();
        const c = document.createElement("canvas");
        c.width = c.height = 64;
        const g = c.getContext("2d"), s = Math.min(img.naturalWidth, img.naturalHeight);
        g.imageSmoothingQuality = "high";
        g.drawImage(img, (img.naturalWidth - s) / 2, (img.naturalHeight - s) / 2, s, s, 0, 0, 64, 64);
        return c.toDataURL("image/png").split(",")[1];
      }, { b64, mime });
      fs.writeFileSync(path.join(out, f + ".png"), Buffer.from(png, "base64"));
    }
    map[k] = { f: f + ".png", img: 1 };
  }
  fs.writeFileSync(path.join(__dirname, "..", "src", "ki-vendor-icons.js"), "var kiVendorIcons=" + JSON.stringify(map) + ";\n");

  const files = [...new Set(Object.values(map).map((v) => v.f))];
  const cell = (f) => {
    const v = Object.values(map).find((x) => x.f === f);
    const data = fs.readFileSync(path.join(out, f)).toString("base64");
    const url = `data:${f.endsWith(".svg") ? "image/svg+xml" : "image/png"};base64,${data}`;
    const ic = v.mono ? `<i style="-webkit-mask:url(${url}) center/contain no-repeat;background:#e8e8ea"></i>` : `<img src="${url}">`;
    return `<div><b>${ic}</b><span>${f.replace(/\.(svg|png)$/, "")}</span></div>`;
  };
  await page.setViewportSize({ width: 900, height: 600 });
  await page.setContent(`<style>body{margin:0;padding:12px;background:#1f1f21;font:11px Segoe UI;color:#bbb;display:grid;grid-template-columns:repeat(8,1fr);gap:10px}
div{display:flex;flex-direction:column;align-items:center;gap:5px}b{width:34px;height:34px;border-radius:8px;background:#2c2c30;display:grid;place-items:center}
img,i{width:20px;height:20px;display:block}img[src*=png]{width:22px;height:22px;border-radius:5px}</style>${files.map(cell).join("")}`);
  await page.screenshot({ path: path.join(__dirname, "..", "tests", "shots", "vendor-sheet.png"), fullPage: true });
  await browser.close();
  const total = fs.readdirSync(out).reduce((n, f) => n + fs.statSync(path.join(out, f)).size, 0);
  console.log(files.length, "icons,", Object.keys(map).length, "vendor keys,", Math.round(total / 1024), "KB");
})();
