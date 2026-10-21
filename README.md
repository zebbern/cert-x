# cert-x

Chrome extension that lets an AI agent use the browser: open pages, click, fill forms, and read what is on screen. The side panel is the chat. Model providers, MCP servers, and approval settings live in the panel.

## Load it

1. Open `chrome://extensions`.
2. Turn on Developer mode.
3. Choose **Load unpacked** and select this folder.
4. Open the cert-x side panel. After a code change, click **Reload** on the extension card.

API keys and MCP tokens stay in Chrome storage on your machine. They are not in this repo.

## Rebuild the panel patches

The side panel and background are built files. Edits to the agent UI, live status bar, and extra tools live in `tools/picker` and are applied on top of the originals:

```text
node tools/picker/apply-picker.js
```

That rewrites `background/background.js`, `chunks/sidepanel-CUbsl7eV.js`, and `assets/sidepanel-DD7JAQkM.css`. Reload the extension after it finishes. The script checks that every file named in `manifest.json` is still on disk.

## MCP

In the side panel, open **Your models**. Under **MCP servers** you can sign in to a remote HTTP server or paste an API key. Postman (US) uses sign-in. Postman (EU) uses a key from the EU account. A local `npx` MCP server cannot run inside the extension.
