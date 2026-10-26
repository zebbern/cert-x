// Pure parts of browse(goal): element extraction from an accessibility tree, the
// decision space offered to the model, secret handling, and answer validation.
const { test } = require("node:test");
const assert = require("node:assert/strict");

// Vendor globals the module uses at call time (same shapes as the bundle's ae / jn).
global.ae = new Set(["button", "link", "textbox", "checkbox", "radio", "combobox", "listbox", "menuitem", "option", "searchbox", "spinbutton", "switch", "tab"]);
global.jn = (node, role) => {
  const p = Object.fromEntries((node.properties || []).map(x => [x.name, x.value?.value])), out = [];
  if (["checkbox", "radio", "switch"].includes(role)) out.push("checked=" + (p.checked === true || p.checked === "true"));
  if (typeof p.expanded === "boolean") out.push("expanded=" + p.expanded);
  if (p.required === true) out.push("required");
  if (p.readonly === true) out.push("readonly");
  if (p.focused === true) out.push("focused");
  return out;
};
const B = require("../src/ki-browse.js");

let next = 1;
function ax(role, name, extra = {}, children = []) {
  const node = { nodeId: String(next++), role: { value: role }, name: { value: name }, backendDOMNodeId: next * 10, properties: [], childIds: [], ...extra };
  node.kids = children;
  return node;
}
function flatten(root) {
  const out = [], walk = n => { out.push(n); n.childIds = n.kids.map(k => k.nodeId); n.kids.forEach(walk); delete n.kids; };
  walk(root);
  return out;
}
const prop = (name, value) => ({ name, value: { value } });
function loginTree() {
  next = 1;
  return flatten(ax("RootWebArea", "Shop", {}, [
    ax("heading", "Sign in"),
    ax("textbox", "Email ", { properties: [prop("editable", "plaintext"), prop("required", true)] }),
    ax("textbox", "Password ", { value: { value: "•••••••" }, properties: [prop("editable", "plaintext")] }),
    ax("combobox", "Country", { value: { value: "Sweden" } }, [
      ax("MenuListPopup", "", {}, [ax("option", "Norway"), ax("option", "Sweden", { properties: [prop("selected", true)] }), ax("group", "More", {}, [ax("option", "Denmark")])])
    ]),
    ax("checkbox", " Remember", { properties: [prop("checked", "true")] }),
    ax("button", "Sign in"),
    ax("button", "Off", { properties: [prop("disabled", true)] }),
    ax("button", "Ghost", { ignored: true }),
    ax("dialog", "Cookies", {}, [ax("button", "Accept")]),
  ]));
}
const register = node => "e" + node.backendDOMNodeId;

test("elements: document order, kinds, native select options, dialogs, disabled and ignored skipped", () => {
  const els = B.kiBrowseElements(loginTree(), register);
  assert.deepEqual(els.map(e => [e.role, e.name, e.kind]), [
    ["textbox", "Email", "field"], ["textbox", "Password", "field"], ["combobox", "Country", "select"],
    ["checkbox", "Remember", "click"], ["button", "Sign in", "click"], ["button", "Accept", "click"]]);
  const select = els.find(e => e.kind === "select");
  assert.deepEqual(select.options.map(({ name, selected }) => ({ name, selected })), [{ name: "Norway", selected: false }, { name: "Sweden", selected: true }, { name: "Denmark", selected: false }]);
  assert.ok(select.options.every(o => o.node != null), "each option keeps its node, so the exact option is selected");
  assert.equal(els.find(e => e.name === "Accept").dialog, "Cookies");
  assert.deepEqual(els.find(e => e.name === "Remember").states, ["checked=true"]);
});

test("space: fixed operation order, value pairs, unselected options only, ENTER/BACK only when earned", () => {
  const obs = { elements: B.kiBrowseElements(loginTree(), register), scrollable: false };
  const values = { email: "alice@example.test", password: "hunter22" };
  const space = B.kiBrowseSpace(obs, values, new Map(), { typed: null, navigated: false });
  assert.deepEqual(Object.keys(space.ops), ["CLICK", "TYPE", "SELECT", "WAIT", "DONE", "BLOCKED"]);
  const email = obs.elements[0].ref;
  assert.deepEqual(Object.keys(space.targets.TYPE).filter(k => k.startsWith(email + "=")), [email + "=email", email + "=password"]);
  assert.equal(Object.keys(space.targets.TYPE).length, 4, "two fields × two values");
  assert.deepEqual(Object.values(space.targets.SELECT).map(d => d.split(" → ")[1]), ['"Norway"', '"Denmark"']);
  assert.ok(!Object.keys(space.targets.CLICK).includes(obs.elements[2].ref), "a native select is chosen by SELECT, not clicked");
  assert.deepEqual(Object.keys(space.selects), [obs.elements[2].ref], "each select has its own option head");
  const later = B.kiBrowseSpace({ ...obs, scrollable: true }, values, new Map(), { typed: email, navigated: true });
  assert.deepEqual(Object.keys(later.ops), ["CLICK", "TYPE", "SELECT", "ENTER", "SCROLL_DOWN", "BACK", "WAIT", "DONE", "BLOCKED"]);
  const none = B.kiBrowseSpace(obs, {}, new Map(), { typed: null, navigated: false });
  assert.ok(!none.ops.TYPE, "TYPE needs at least one provided value");
});

test("secrets: typed fields are shown by name whatever the page made of them", () => {
  const els = B.kiBrowseElements(loginTree(), register), values = { email: "alice@example.test", password: "hunter2" };
  const password = els[1], filled = new Map([[password.ref, "password"]]);
  assert.equal(B.kiBrowseHolds(password, values, filled), "password", "a typed field holds its value even when masked");
  assert.equal(B.kiBrowseHolds({ ...password, value: "1234 5678" }, { pin: "12345678" }, new Map([[password.ref, "pin"]])), "pin", "reformatted or truncated, a typed field still holds the name");
  assert.equal(B.kiBrowseHolds({ ...password, value: "" }, values, filled), null, "a field the page cleared holds nothing");
  assert.equal(B.kiBrowseHolds(password, values, new Map()), null, "an unrelated masked value is not claimed");
  const email = { ...els[0], value: "alice@example.test" };
  assert.equal(B.kiBrowseHolds(email, values, new Map()), "email");
  const described = B.kiBrowseDescribe(email, "email");
  assert.ok(described.includes("holds email") && !described.includes("alice@"), described);
  assert.equal(B.kiBrowseDescribe({ ...password, type: "password" }, null).includes("•"), false, "masked text is described as filled");
});

test("redaction: every form a value takes on the page is replaced by its name", () => {
  const values = { email: "Alice@Example.test", query: "laptop stand", card: "4242424242424242", cvc: "737", qty: "1" };
  const redact = B.kiBrowseRedactor(values);
  assert.equal(redact("Signed in as alice@example.test"), "Signed in as ‹email›", "case-insensitive");
  assert.equal(redact("/search?q=laptop+stand&next=laptop%20stand"), "/search?q=‹query›&next=‹query›", "form- and URL-encoded");
  assert.equal(redact("/challenge?identifier=Alice%40Example.test"), "/challenge?identifier=‹email›");
  assert.equal(redact("Card 4242 4242 4242 4242 saved"), "Card ‹card› saved", "digits with the separators a page adds");
  assert.equal(redact("Qty 1 of 10, CVC 737 needed"), "Qty 1 of 10, CVC 737 needed", "short values are not matched inside free text");
  const deep = B.kiBrowseRedactDeep({ url: "https://x.test/?q=laptop+stand", list: ["laptop  stand"], n: 3, keep: { "e1=query": "x" } }, B.kiBrowseRedactor({ query: "laptop  stand" }));
  assert.deepEqual(deep, { url: "https://x.test/?q=‹query›", list: ["‹query›"], n: 3, keep: { "e1=query": "x" } }, "strings anywhere, keys untouched");
  // Short values are hidden structurally: the typed field's own line in the page text.
  const cvc = { ref: "e20", role: "textbox", name: "CVC", kind: "field", value: "737" };
  const obs = { url: "u", title: "t", text: '- textbox "CVC" [ref=e20, required]: 737\n- text: Qty 1 of 10', truncated: false, elements: [cvc] };
  const space = B.kiBrowseSpace(obs, { cvc: "737" }, new Map([["e20", "cvc"]]), { typed: null, navigated: false });
  const state = B.kiBrowseState("Pay", obs, { cvc: "737" }, space, []);
  assert.equal(state.page, '- textbox "CVC" [ref=e20, required]: ‹cvc›\n- text: Qty 1 of 10');
  assert.ok(!JSON.stringify(state).includes("737"), JSON.stringify(state));
});

test("state: value names only, truncation and limits are stated, history is kept short", () => {
  const els = B.kiBrowseElements(loginTree(), register), values = { email: "alice@example.test", password: "hunter2" };
  const space = { ...B.kiBrowseSpace({ elements: els, scrollable: false }, values, new Map(), { typed: null, navigated: false }), omitted: 3 };
  const state = B.kiBrowseState("Sign in", { url: "https://x.test/", title: "x", text: '- heading "Sign in"', truncated: true, elements: els }, values, space, [{ text: 'type email into textbox "Email" @e1', changed: true }]);
  assert.deepEqual(Object.keys(state.values), ["email", "password"]);
  assert.ok(!JSON.stringify(state).includes("hunter2"));
  assert.ok(state.page.endsWith("[page text truncated]") && /3 more/.test(state.not_offered));
  assert.deepEqual(state.recent_actions, [{ action: 'type email into textbox "Email" @e1', page_changed: true }]);
});

test("space: a value typed into a password field is offered to password fields only", () => {
  const els = B.kiBrowseElements(loginTree(), register).map(el => el.name === "Password" ? { ...el, type: "password" } : el);
  const space = B.kiBrowseSpace({ elements: els, scrollable: false }, { password: "hunter22" }, new Map(), { typed: null, navigated: false, secret: new Set(["password"]) });
  assert.deepEqual(Object.values(space.targets.TYPE).map(d => d.split(" ")[1]), ['"Password"']);
});

test("space: over the 255-option cap, dialog controls and fields are kept and the rest is counted", () => {
  next = 1;
  const links = Array.from({ length: 300 }, (_, i) => ax("link", "Product " + i));
  const tree = flatten(ax("RootWebArea", "Big", {}, [...links, ax("textbox", "Search", { properties: [prop("editable", "plaintext")] }), ax("dialog", "Consent", {}, [ax("button", "Accept all")])]));
  const obs = { elements: B.kiBrowseElements(tree, register), scrollable: true };
  const space = B.kiBrowseSpace(obs, { q: "laptop" }, new Map(), { typed: null, navigated: false });
  const click = Object.values(space.targets.CLICK);
  assert.equal(click.length, B.KI_BROWSE_OPTIONS);
  assert.ok(click.some(d => d.includes('"Accept all"')) && click.some(d => d.includes('"Search"')), "dialog control and field survive the cap");
  assert.equal(space.omitted, 302 - B.KI_BROWSE_OPTIONS);
  assert.equal(space.index.length, B.KI_BROWSE_OPTIONS, "the element index lists exactly the offered elements");
  assert.ok(space.index.some(line => /Accept all/.test(line)));
  const state = B.kiBrowseState("Accept cookies", { url: "u", title: "t", text: "x".repeat(20000), truncated: false, elements: obs.elements }, { q: "laptop" }, space, []);
  assert.ok(JSON.stringify(state.elements).length + state.page.length < 20000 && state.page.endsWith("[page text truncated]"), "index and page text share one budget");
  const questions = B.kiBrowseQuestions("Accept cookies, then search for q", space);
  for (const q of Object.values(questions)) if (q.type === "choice") assert.ok(Object.keys(q.criteria).length <= B.KI_BROWSE_OPTIONS);
  assert.deepEqual(Object.keys(questions), ["operation", "goal_done", "click_target", "type_target"]);
  assert.equal(questions.goal_done.type, "noul", "DONE is checked by a separate yes/no question");
  assert.equal(questions.click_target.instructions.operation, "CLICK");
});

test("elements: identical controls carry the nearest named container or preceding heading", () => {
  next = 1;
  const tree = flatten(ax("RootWebArea", "Shop", {}, [
    ax("heading", "Blue Kettle"), ax("button", "Add to cart"),
    ax("heading", "Brass Lamp"), ax("button", "Add to cart"),
    ax("listitem", "Red Mug", {}, [ax("button", "Add to cart")]),
    ax("button", "Checkout"),
  ]));
  const els = B.kiBrowseElements(tree, register);
  assert.deepEqual(els.map(e => e.near), ["Blue Kettle", "Brass Lamp", "Red Mug", undefined], "unique controls carry no context");
  assert.match(B.kiBrowseDescribe(els[1], null), /^button "Add to cart" near "Brass Lamp"$/);
});

test("answers: only a well-formed distribution whose choice is the top option is accepted", () => {
  const ids = ["CLICK", "DONE"];
  assert.deepEqual(B.kiBrowseChoice({ choice: "CLICK", probabilities: { CLICK: 0.9, DONE: 0.1 }, confidence: 0.8 }, ids, "operation"), { choice: "CLICK", p: 0.9 });
  for (const bad of [
    { choice: "SUBMIT", probabilities: { CLICK: 0.9, DONE: 0.1 } },
    { choice: "CLICK", probabilities: { CLICK: 0.9 } },
    { choice: "CLICK", probabilities: { CLICK: 0.6, DONE: 0.6 } },
    { choice: "DONE", probabilities: { CLICK: 0.9, DONE: 0.1 } },
    { choice: "CLICK", probabilities: { CLICK: NaN, DONE: 0.1 } },
    null,
  ]) assert.throws(() => B.kiBrowseChoice(bad, ids, "operation"), e => e.retryable === true && /nothing was executed/.test(e.message));
});

test("DONE stands only when the separate goal check agrees; otherwise the likeliest action runs", () => {
  const space = { ops: { CLICK: "", TYPE: "", ENTER: "", WAIT: "", DONE: "", BLOCKED: "" }, targets: { CLICK: { e1: "", e2: "" }, TYPE: { "e3=q": "" }, SELECT: {} } };
  const answers = noul => ({
    operation: { choice: "DONE", probabilities: { CLICK: 0.02, TYPE: 0, ENTER: 0.43, WAIT: 0.01, DONE: 0.54, BLOCKED: 0 } },
    goal_done: { type: "noul", noul },
    click_target: { choice: "e2", probabilities: { e1: 0.1, e2: 0.9 } },
  });
  assert.deepEqual(B.kiBrowseFromAnswers(answers(0.2), space), { op: "ENTER", target: null, p: 0.43 }, "unsubmitted search: press Enter instead of claiming done");
  assert.equal(B.kiBrowseFromAnswers(answers(0.9), space).op, "DONE");
  const click = answers(0.1); click.operation.probabilities = { CLICK: 0.4, TYPE: 0, ENTER: 0, WAIT: 0, DONE: 0.6, BLOCKED: 0 };
  assert.deepEqual(B.kiBrowseFromAnswers(click, space), { op: "CLICK", target: "e2", p: 0.4 }, "the fallback uses the speculative target head");
  assert.equal(B.kiBrowseFromAnswers({ ...answers(0.1), goal_done: undefined }, space).op, "ENTER", "a missing check does not confirm DONE");
});

test("DONE with an unconvincing runner-up stops as unconfirmed instead of guessing an action", () => {
  const space = { ops: { CLICK: "", WAIT: "", DONE: "", BLOCKED: "" }, targets: { CLICK: { e1: 'button "Delete account"' }, TYPE: {}, SELECT: {} }, selects: {} };
  const answers = { operation: { choice: "DONE", probabilities: { CLICK: 0.02, WAIT: 0.02, DONE: 0.96, BLOCKED: 0 } }, goal_done: { noul: 0.48 }, click_target: { choice: "e1", probabilities: { e1: 1 } } };
  assert.deepEqual(B.kiBrowseFromAnswers(answers, space), { op: "DONE", target: null, p: 0.96, unconfirmed: true });
  answers.operation.probabilities = { CLICK: 0, WAIT: 0.4, DONE: 0.6, BLOCKED: 0 };
  assert.equal(B.kiBrowseFromAnswers(answers, space).unconfirmed, true, "WAIT is never the fallback: a finished page would wait out the budget");
});

test("SELECT: the dropdown and its option come from separate heads, one budget per dropdown", () => {
  next = 1;
  const country = ax("combobox", "Country", { value: { value: "Sweden" } }, [ax("MenuListPopup", "", {}, Array.from({ length: 300 }, (_, i) => ax("option", i ? "Land " + i : "Sweden", i ? {} : { properties: [prop("selected", true)] })))]);
  const state = ax("combobox", "State", { value: { value: "" } }, [ax("MenuListPopup", "", {}, [ax("option", "Ohio"), ax("option", "Texas")])]);
  const els = B.kiBrowseElements(flatten(ax("RootWebArea", "Form", {}, [country, state])), register);
  const space = B.kiBrowseSpace({ elements: els, scrollable: false }, {}, new Map(), { typed: null, navigated: false });
  const [c, s] = els.map(el => el.ref);
  assert.equal(Object.keys(space.selects[c].options).length, B.KI_BROWSE_OPTIONS);
  assert.deepEqual(Object.values(space.selects[s].options).map(d => d.split(" → ")[1]), ['"Ohio"', '"Texas"'], "the long list does not crowd out the next dropdown");
  assert.equal(space.omitted, 299 - B.KI_BROWSE_OPTIONS);
  const q = B.kiBrowseQuestions("State Texas", space);
  assert.ok(q.select_target && q["option_" + c] && q["option_" + s]);
  const answers = { operation: { choice: "SELECT", probabilities: { SELECT: 0.9, WAIT: 0.05, DONE: 0.03, BLOCKED: 0.02 } }, goal_done: { noul: 0 },
    select_target: { choice: s, probabilities: { [c]: 0.1, [s]: 0.9 } },
    ["option_" + s]: { choice: s + ":1", probabilities: { [s + ":0"]: 0.05, [s + ":1"]: 0.95 } },
    ["option_" + c]: { choice: c + ":1", probabilities: Object.fromEntries(Object.keys(space.selects[c].options).map((k, i) => [k, i ? 0 : 1])) } };
  assert.deepEqual(B.kiBrowseFromAnswers(answers, space), { op: "SELECT", target: s + ":1", p: 0.9 });
});
