// Downloads everything vendor-icons.js needs into %TEMP%\kiicons:
// the @lobehub/icons-static-svg package (MIT), Hugging Face org avatars, and
// the OpenRouter model list (used by logo-test.js).
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const dir = path.join(process.env.TEMP, "kiicons");
const out = path.join(dir, "avatars");
fs.mkdirSync(out, { recursive: true });
const hf = {
  thinkingmachines: ["thinkingmachines", "thinking-machines-lab"],
  inclusionai: ["inclusionAI"],
  moondream: ["moondream", "vikhyatk"],
  thedrummer: ["TheDrummer"],
  sao10k: ["Sao10K"],
  nexagi: ["nex-agi"],
  anthracite: ["anthracite-org"],
  gryphe: ["Gryphe"],
  writer: ["Writer"],
  elorian: ["elorian"],
  xingchen: ["xingchen-agi"],
  scaledown: ["scaledown"],
  inferencenet: ["inference-net"],
  typesafe: ["typesafe"],
};
const favicons = { reflection: "reflection.ai" };

(async () => {
  if (!fs.existsSync(path.join(dir, "package", "icons"))) {
    execSync("npm pack @lobehub/icons-static-svg --silent", { cwd: dir });
    const tgz = fs.readdirSync(dir).find((f) => f.endsWith(".tgz"));
    execSync(`tar -xzf ${tgz}`, { cwd: dir });
  }
  fs.writeFileSync(path.join(dir, "models.json"), Buffer.from(await (await fetch("https://openrouter.ai/api/v1/models")).arrayBuffer()));
  for (const [key, orgs] of Object.entries(hf)) {
    let got = "";
    for (const o of orgs) {
      for (const kind of ["organizations", "users"]) {
        try {
          const r = await fetch(`https://huggingface.co/api/${kind}/${o}/avatar`);
          if (!r.ok) continue;
          const { avatarUrl } = await r.json();
          if (!avatarUrl) continue;
          const img = await fetch(avatarUrl.startsWith("http") ? avatarUrl : "https://huggingface.co" + avatarUrl);
          if (!img.ok) continue;
          const type = img.headers.get("content-type") || "";
          const ext = type.includes("svg") ? "svg" : type.includes("png") ? "png" : type.includes("webp") ? "webp" : "jpg";
          fs.writeFileSync(path.join(out, `${key}.${ext}`), Buffer.from(await img.arrayBuffer()));
          got = `${kind}/${o}`;
          break;
        } catch {}
      }
      if (got) break;
    }
    console.log(key.padEnd(18), got || "-");
  }
  for (const [key, domain] of Object.entries(favicons)) {
    const r = await fetch(`https://www.google.com/s2/favicons?domain=${domain}&sz=128`);
    if (r.ok) fs.writeFileSync(path.join(out, `${key}.png`), Buffer.from(await r.arrayBuffer()));
    console.log(key.padEnd(18), r.ok ? "favicon " + domain : "-");
  }
})();
