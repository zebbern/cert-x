function KiConnectionsSettings({ lang, onOpen, connected = false }) {
  const zh = lang === "zh-CN";
  const rows = [
    ["security", "Security testing", "Scans, accounts, and evidence", "M12 3l8 3v6c0 5-8 9-8 9S4 17 4 12V6l8-3ZM8 12h8M12 8v8"],
    ["health", zh ? "功能状态" : "Capability health", zh ? "检查连接与工具" : "Check connections and tools", "M3 12h4l3-7 4 14 3-7h4"],
    ["models", zh ? "模型" : "Models", zh ? "添加模型提供方" : "Manage model providers", "M8 3h8v3h3v12H5V6h3V3ZM8 9h8v6H8V9Z"],
    ["mcp", zh ? "MCP 服务器" : "MCP servers", zh ? "连接远程或本机工具" : "Connect remote or local tools", "M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-2 2M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l2-2"],
    ["local", zh ? "本机" : "Local computer", zh ? "文件与命令" : "Files and commands", "M3 4h18v13H3V4ZM8 21h8M12 17v4"],
    ["browser", zh ? "浏览器控制" : "Browser control", connected ? (zh ? "已连接" : "Connected") : (zh ? "未连接" : "Not connected"), "M3 4h18v16H3V4ZM3 9h18M6 6.5h.01M9 6.5h.01M10 12l5 3-3 1-1 3-1-7Z"],
  ];
  return (0, A.jsxs)("div", { className: "wb-set-group", children: [
    (0, A.jsx)("div", { className: "wb-set-group-label", children: zh ? "连接" : "Connections" }),
    (0, A.jsx)("div", { className: "wb-set-card", children: rows.map(([id, label, subtitle, path]) =>
      (0, A.jsxs)("button", { type: "button", className: "wb-set-row wb-set-navrow", onClick: () => onOpen(id), children: [
        (0, A.jsx)("svg", { className: "wb-set-row-icon", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.6, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true, children: (0, A.jsx)("path", { d: path }) }),
        (0, A.jsxs)("span", { className: "wb-set-row-text", children: [
          (0, A.jsx)("span", { className: "wb-set-row-label", children: label }),
          (0, A.jsx)("span", { className: "wb-set-row-sub", children: subtitle }),
        ] }),
        (0, A.jsx)(ht, { className: "wb-set-row-chevron", "aria-hidden": true }),
      ] }, id)) }),
  ] });
}

function KiContextSettingsEntry({ onOpen }) {
  const rows = [["profiles", "Profiles", "Choose how the agent works", "M4 6h16M4 12h16M4 18h16M8 3v6M16 9v6M10 15v6"],
    ["workspaces", "Workspaces", "Keep project context together", "M3 6h7l2 2h9v12H3V6Z"]];
  return (0, A.jsxs)("div", { className: "wb-set-group", children: [
    (0, A.jsx)("div", { className: "wb-set-group-label", children: "Agent" }),
    (0, A.jsx)("div", { className: "wb-set-card", children: rows.map(([id, name, subtitle, path]) => (0, A.jsxs)("button", {
      type: "button", className: "wb-set-row wb-set-navrow", onClick: () => onOpen(id), children: [
        (0, A.jsx)("svg", { className: "wb-set-row-icon", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.6, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true, children: (0, A.jsx)("path", { d: path }) }),
        (0, A.jsxs)("span", { className: "wb-set-row-text", children: [(0, A.jsx)("span", { className: "wb-set-row-label", children: name }), (0, A.jsx)("span", { className: "wb-set-row-sub", children: subtitle })] }),
        (0, A.jsx)(ht, { className: "wb-set-row-chevron", "aria-hidden": true }),
      ],
    }, id)) }),
  ] });
}

function KiToolsSettingsEntry({ lang, onOpen }) {
  return (0, A.jsx)("div", { className: "wb-set-group", children: (0, A.jsx)("div", { className: "wb-set-card", children:
    (0, A.jsxs)("button", { type: "button", className: "wb-set-row wb-set-navrow", onClick: () => onOpen("tools"), children: [
      (0, A.jsx)("svg", { className: "wb-set-row-icon", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.6, "aria-hidden": true, children: (0, A.jsx)("path", { d: "M12 3l8 3v6c0 5-8 9-8 9S4 17 4 12V6l8-3ZM8 12l3 3 5-6" }) }),
      (0, A.jsx)("span", { className: "wb-set-row-label", children: lang === "zh-CN" ? "工具与权限" : "Tools & permissions" }),
      (0, A.jsx)(ht, { className: "wb-set-row-chevron", "aria-hidden": true }),
    ] }) }) });
}
function KiPolicyIndicator({ lang }) {
  const [active, setActive] = (0, _.useState)(false);
  (0, _.useEffect)(() => {
    let mounted = true;
    const update = policy => { if (mounted) setActive([policy?.groups, policy?.tools].some(bucket => Object.values(bucket || {}).some(value => ["ask", "allow", "disabled"].includes(value)))); };
    chrome.storage.local.get("ki_tool_permissions").then(data => update(data.ki_tool_permissions)).catch(() => {});
    const listener = (changes, area) => { if (area === "local" && changes.ki_tool_permissions) update(changes.ki_tool_permissions.newValue); };
    chrome.storage.onChanged.addListener(listener);
    return () => { mounted = false; chrome.storage.onChanged.removeListener(listener); };
  }, []);
  return active ? (0, A.jsx)("span", { title: lang === "zh-CN" ? "工具权限覆盖了当前模式" : "Tool permissions override the current mode", children: lang === "zh-CN" ? " · 自定义" : " · Overrides" }) : null;
}
