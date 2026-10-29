// Exposes background "daemon" tools that already have full execute() implementations
// but were never advertised to the model. Each tool needs an entry in BOTH the
// model-facing schema table (pP) and the executor map (mP). classMap pins the
// minified class id -> tool name so apply-picker.js fails loudly if a future
// bundle renames them instead of silently shipping a broken tool.

const classMap = {
  Ki: "set_checked",
  ri: "cdp",
  ji: "list_browser_tabs",
  Mi: "attach_tab",
  Ni: "activate_tab",
  _a: "inspect_region",
  va: "highlight_region",
  ya: "clear_highlight",
};

// Executor-map (mP) source text, in a stable order. These reference the minified
// class identifiers verified by classMap.
const mpEntries =
  "list_browser_tabs:new ji,attach_tab:new Mi,activate_tab:new Ni," +
  "set_checked:new Ki,cdp:new ri,inspect_region:new _a," +
  "highlight_region:new va,clear_highlight:new ya," +
  // save_file and browse are new tools implemented in ki-background.js and
  // ki-browse.js (injected at the top of the IIFE, so their classes are in scope
  // here where mP is defined).
  "save_file:new kiSaveFileTool,browse:new kiBrowseTool,";

// Schema table (pP) entries. Keys match mP and the executor classes' name=.
// permissionAction must be one of: navigate, read_page, interact, execute_js, manage_tabs.
// Omit attachesBeforeRun to attach the debugger to the working tab first (needed for
// tools that drive the page via CDP); set it false for pure tab-management queries.
const specs = {
  list_browser_tabs: {
    description:
      "List every open browser tab across all windows (not only this conversation's tabs), each with tabId, windowId, url, title, and active state. Use to find a tab the user opened manually, then attach_tab to take it over.",
    parameters: { type: "object", properties: {} },
    permissionAction: "read_page",
    attachesBeforeRun: false,
  },
  attach_tab: {
    description:
      "Make an already-open browser tab the working tab and bind it to this conversation, so later tools act on it. Pass a tabId from list_browser_tabs. Use to take over a tab the user already has open instead of navigating a fresh one.",
    parameters: {
      type: "object",
      properties: {
        tabId: { type: "number", description: "tabId (from list_browser_tabs) to attach and make the working tab." },
      },
      required: ["tabId"],
    },
    permissionAction: "manage_tabs",
    attachesBeforeRun: false,
  },
  activate_tab: {
    description:
      "Bring the working tab to the foreground (make it the active tab in its window), optionally focusing its window too. Use when the user needs to actually see the tab you are working on.",
    parameters: {
      type: "object",
      properties: {
        focus_window: { type: "boolean", description: "When true, also focus the tab's window. Defaults to false." },
      },
    },
    permissionAction: "manage_tabs",
    attachesBeforeRun: false,
  },
  set_checked: {
    description:
      "Set a checkbox, switch, or radio control to a desired checked state, then verify the state actually changed. Prefer this over click for toggles because it confirms the result. Radio controls cannot be unchecked directly.",
    parameters: {
      type: "object",
      properties: {
        target: { type: "string", description: "CSS selector or @ref ID (from a snapshot) of the checkbox, switch, or radio." },
        checked: { type: "boolean", description: "Desired state: true to check/enable, false to uncheck." },
      },
      required: ["target", "checked"],
    },
    permissionAction: "interact",
  },
  cdp: {
    description:
      "Raw Chrome DevTools Protocol escape hatch on the working tab. Prefer screenshot for ordinary page or element screenshots; Page.captureScreenshot is also returned as a rendered image, with its CDP parameters preserved. Prefer save_as_pdf for PDFs; Page.printToPDF returns an Outputs artifact, while explicitly requested stream handles stay raw. Use CDP for capabilities the other tools do not cover, such as DOM/CSS inspection, Network domain, or Emulation.setFocusEmulationEnabled. Target.activateTarget is refused; call Page.bringToFront instead.",
    parameters: {
      type: "object",
      properties: {
        method: { type: "string", description: "CDP method name, e.g. 'Runtime.evaluate' or 'DOM.getDocument'." },
        params: { type: "object", description: "Parameters object for the method; omit when the method takes none.", additionalProperties: true },
      },
      required: ["method"],
    },
    permissionAction: "execute_js",
  },
  inspect_region: {
    description:
      "Report geometry and box-model details for an element and up to a few of its ancestors on the working tab. Useful for canvas/map-like targets or deciding where to click by coordinates. Call with capabilities:true first to discover options.",
    parameters: {
      type: "object",
      properties: {
        target: { type: "string", description: "CSS selector or @ref ID of the element to inspect." },
        selector: { type: "string", description: "Alias for target." },
        max_ancestors: { type: "number", description: "How many ancestor boxes to include, 0 to 8 (default 5)." },
        capabilities: { type: "boolean", description: "When true, return this tool's capabilities instead of inspecting; cannot be combined with a target." },
      },
    },
    permissionAction: "read_page",
  },
  highlight_region: {
    description:
      "Draw a temporary visual outline around an element on the working tab so the user can see what you are about to act on. Returns a highlight_id you can renew or clear; the outline auto-expires after duration_ms.",
    parameters: {
      type: "object",
      properties: {
        target: { type: "string", description: "CSS selector or @ref ID of the element to highlight." },
        selector: { type: "string", description: "Alias for target." },
        duration_ms: { type: "number", description: "How long the outline stays, 1000 to 120000 ms (default 30000)." },
        highlight_id: { type: "string", description: "Pass an existing id (with no target) to renew that highlight's timer." },
      },
    },
    permissionAction: "read_page",
  },
  clear_highlight: {
    description: "Remove a highlight created by highlight_region, using its highlight_id.",
    parameters: {
      type: "object",
      properties: {
        highlight_id: { type: "string", description: "The id returned by highlight_region." },
      },
      required: ["highlight_id"],
    },
    permissionAction: "read_page",
  },
  save_file: {
    description:
      "Save content to the user's Downloads folder (the mirror of read_file/download). Provide a relative filename and the content, as UTF-8 text by default or base64 bytes when encoding is 'base64' for binary. Saves straight to Downloads without a dialog; it cannot write to arbitrary paths.",
    parameters: {
      type: "object",
      properties: {
        filename: { type: "string", description: "Relative file name inside Downloads, e.g. 'report.txt' or 'out/data.json'. No absolute paths, drive letters, or '..'." },
        content: { type: "string", description: "The data to write: UTF-8 text, or base64-encoded bytes when encoding is 'base64'." },
        encoding: { type: "string", enum: ["text", "base64"], description: "How to interpret content: 'text' (default) writes UTF-8; 'base64' decodes to raw bytes." },
      },
      required: ["filename", "content"],
    },
    permissionAction: "read_page",
    attachesBeforeRun: false,
  },
  // Advertised only while a decision backend is configured (kiBrowseReady in apply-picker).
  browse: {
    description:
      "Do a whole page task in one call; prefer it over snapshot then click/fill/select whenever the task takes more than one action (sign in, fill and submit a form, get past a banner, open each section of an app). A fast model acts until the goal is visibly done. Put text to type in values and name them in goal; returns the steps and the final page with refs.",
    parameters: {
      type: "object",
      properties: {
        goal: { type: "string", description: "What must be visibly true when done, e.g. 'sign in, then open Settings > API keys'." },
        values: { type: "object", additionalProperties: { type: "string" }, description: "Exact text to type, keyed by the names goal uses, e.g. {\"email\":\"a@b.c\",\"password\":\"...\"}. Only the names reach the decision model." },
        url: { type: "string", description: "Optional page to open first." },
        max_steps: { type: "number", description: "Action budget 1-60 (default 25)." },
      },
      required: ["goal"],
    },
    permissionAction: "interact",
  },
};

const toolNames = Object.keys(specs);
const specEntries = toolNames.map((n) => n + ":" + JSON.stringify(specs[n])).join(",") + ",";

// Of the exposed tools, these act on the page / a working tab, so they should
// accept the optional `tab` argument (route to a specific session tab) exactly
// like navigate/click/etc. do. The three tab-management tools
// (list_browser_tabs, attach_tab, activate_tab) are intentionally excluded: a
// `tab` argument is meaningless for them. This list is spliced into BOTH the
// schema-augmentation loop and the kP execution guard so the two stay in sync.
const tabCapable = ["cdp", "set_checked", "inspect_region", "highlight_region", "clear_highlight", "browse"];
const tabListSuffix = tabCapable.map((n) => ",`" + n + "`").join("");

module.exports = { classMap, mpEntries, specs, specEntries, toolNames, tabCapable, tabListSuffix };
