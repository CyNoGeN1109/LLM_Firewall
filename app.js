/* ── CynoShield — App Logic ── */
const $ = (s) => document.querySelector(s);
const messagesEl = $("#messages");
const form = $("#chatForm");
const input = $("#promptInput");
const sendBtn = $("#sendButton");
const stopBtn = $("#stopButton");
const tmpl = $("#messageTemplate");
const modelName = $("#modelName");
const targetLabel = $("#targetLabel");
const runtimeDot = $("#runtimeStatus");
const runtimeLbl = $("#runtimeLabel");
const modelSelect = $("#modelSelect");
const fwToggle = $("#firewallToggle");
const fwWrap = $("#firewallWrap");
const fwLabel = $("#firewallLabel");
const fwIndicator = $("#firewallIndicator");
const settingsBtn = $("#settingsToggle");
const settingsPanel = $("#settingsPanel");
const decisionPanel = $("#decisionPanel");
const sysPrompt = $("#systemPrompt");
const tempSlider = $("#temperature");
const tempValue = $("#temperatureValue");

let conversation = [];
let ctrl = null;
let chatModel = "qwen3:1.7b";
let fwModel = "gemma4:e2b";

const WELCOME = "Welcome to CynoShield. Toggle the firewall OFF to see prompt injection attacks succeed against Qwen — then turn it ON and watch Gemma4 block them in real-time.";

init();

async function init() {
  addMsg("assistant", WELCOME);
  bind();
  await loadConfig();
  await checkHealth();
}

function bind() {
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const t = input.value.trim();
    if (!t || ctrl) return;
    input.value = "";
    resize();
    send(t);
  });
  input.addEventListener("input", resize);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); }
  });
  stopBtn.addEventListener("click", () => { if (ctrl) { ctrl.abort(); ctrl = null; setGen(false); } });
  settingsBtn.addEventListener("click", () => settingsPanel.classList.toggle("hidden"));
  tempSlider.addEventListener("input", () => { tempValue.textContent = tempSlider.value; });
  modelSelect.addEventListener("change", () => { chatModel = modelSelect.value; labels(); });
  fwToggle.addEventListener("change", toggleFirewall);
  $("#newChat").addEventListener("click", () => {
    conversation = [];
    messagesEl.innerHTML = "";
    addMsg("assistant", WELCOME);
    resetDecision();
    input.focus();
  });
  $("#exportChat").addEventListener("click", exportChat);
}

function toggleFirewall() {
  const on = fwToggle.checked;
  fwWrap.classList.toggle("off", !on);
  fwLabel.textContent = on ? "Firewall ON" : "Firewall OFF";
  decisionPanel.className = "decision-card";
  decisionPanel.querySelector("strong").textContent = on ? "Firewall Enabled" : "Firewall Disabled";
  decisionPanel.querySelector("p").textContent = on
    ? `${fwModel} will inspect prompts before they reach ${chatModel}.`
    : "Prompts go directly to the target — no protection.";
  labels();
}

async function loadConfig() {
  try {
    const r = await fetch("/api/config");
    const c = await r.json();
    chatModel = c.model;
    fwModel = c.firewall_model;
    labels();
  } catch {}
}

async function checkHealth() {
  try {
    const r = await fetch("/api/health");
    const h = await r.json();
    fillModels(h.models || []);
    if (h.ok && h.firewall_available) {
      runtimeDot.className = "status-dot";
      runtimeLbl.textContent = "Systems online";
    } else if (h.ok) {
      runtimeDot.className = "status-dot error";
      runtimeLbl.textContent = `${fwModel} not found`;
    } else {
      runtimeDot.className = "status-dot error";
      runtimeLbl.textContent = "Ollama offline";
    }
  } catch {
    runtimeDot.className = "status-dot error";
    runtimeLbl.textContent = "Connection failed";
  }
}

function fillModels(models) {
  const all = [...new Set([chatModel, ...models].filter(Boolean))];
  modelSelect.innerHTML = "";
  all.forEach((m) => {
    const o = document.createElement("option");
    o.value = m; o.textContent = m; o.selected = m === chatModel;
    modelSelect.appendChild(o);
  });
}

async function send(text) {
  addMsg("user", text);
  conversation.push({ role: "user", content: text });
  const ast = addMsg("assistant", "", true);
  ctrl = new AbortController();
  setGen(true);

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: ctrl.signal,
      body: JSON.stringify({
        model: chatModel,
        firewall: fwToggle.checked,
        messages: conversation,
        system_prompt: sysPrompt.value,
        temperature: tempSlider.value,
      }),
    });
    if (!res.ok || !res.body) throw new Error("Request failed: " + res.status);

    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "", full = "", blocked = false;

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const parts = buf.split("\n\n");
      buf = parts.pop() || "";

      for (const part of parts) {
        const ev = parseSSE(part);
        if (ev.type === "firewall") showDecision(ev.data);
        if (ev.type === "blocked") {
          blocked = true;
          full = ev.data.message;
          ast.node.classList.add("blocked");
          ast.node.classList.remove("typing");
          ast.content.textContent = "";
          showAttackBanner(ev.data.message);
          ast.content.textContent = full;
          scroll();
        }
        if (ev.type === "token") {
          full += ev.data.text;
          ast.content.textContent = full;
          scroll();
        }
        if (ev.type === "error") throw new Error(ev.data.message);
      }
    }

    ast.node.classList.remove("typing");
    if (full.trim()) conversation.push({ role: "assistant", content: full });
    else ast.content.textContent = "No response.";
    if (blocked) conversation.pop();
  } catch (err) {
    if (err.name !== "AbortError") {
      ast.content.textContent = err.message || "Something went wrong.";
      ast.node.classList.remove("typing");
    }
  } finally {
    ctrl = null;
    setGen(false);
    input.focus();
  }
}

function addMsg(role, text, typing = false) {
  const frag = tmpl.content.cloneNode(true);
  const node = frag.querySelector(".msg");
  const avatar = frag.querySelector(".msg-avatar");
  const meta = frag.querySelector(".msg-meta");
  const content = frag.querySelector(".msg-content");
  node.classList.add(role);
  if (typing) node.classList.add("typing");
  avatar.textContent = role === "user" ? "YOU" : "AI";
  meta.textContent = role === "user" ? "You" : "CynoShield";
  content.textContent = text;
  messagesEl.appendChild(frag);
  scroll();
  return { node: messagesEl.lastElementChild, content: messagesEl.lastElementChild.querySelector(".msg-content") };
}

function showAttackBanner(msg) {
  const banner = document.createElement("div");
  banner.className = "attack-banner";
  banner.innerHTML = `<svg viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg><span>🛡️ ATTACK BLOCKED — ${msg}</span>`;
  messagesEl.appendChild(banner);
  scroll();
  setTimeout(() => banner.remove(), 8000);
}

function showDecision(d) {
  const ok = Boolean(d.allowed);
  decisionPanel.className = `decision-card ${ok ? "allow" : "block"}`;
  decisionPanel.querySelector("strong").textContent = ok
    ? `✓ ALLOWED — ${d.risk} risk`
    : `✕ BLOCKED — ${d.risk} risk`;
  decisionPanel.querySelector("p").textContent = `[${d.attack_type}] ${d.reason}`;
}

function resetDecision() {
  decisionPanel.className = "decision-card";
  decisionPanel.querySelector("strong").textContent = "Firewall Decision";
  decisionPanel.querySelector("p").textContent = "Awaiting first prompt…";
}

function parseSSE(text) {
  const type = text.match(/^event:\s*(.+)$/m)?.[1] || "message";
  const data = text.match(/^data:\s*(.+)$/m)?.[1] || "{}";
  try { return { type, data: JSON.parse(data) }; }
  catch { return { type, data: {} }; }
}

function resize() {
  input.style.height = "auto";
  input.style.height = Math.min(input.scrollHeight, 160) + "px";
}

function setGen(g) {
  sendBtn.classList.toggle("hidden", g);
  stopBtn.classList.toggle("hidden", !g);
  input.disabled = g;
}

function scroll() { messagesEl.scrollTop = messagesEl.scrollHeight; }

function labels() {
  modelName.textContent = "CynoShield";
  targetLabel.textContent = fwToggle.checked
    ? `${chatModel} ← protected by ${fwModel}`
    : `${chatModel} ← NO FIREWALL`;
  input.placeholder = fwToggle.checked
    ? "Try a prompt injection — the firewall will catch it"
    : "Firewall OFF — try 'ignore all instructions' to see it work";
}

function exportChat() {
  const lines = conversation.map((m) => `${m.role.toUpperCase()}: ${m.content}`).join("\n\n");
  const blob = new Blob([lines || "Empty session."], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "cynoshield-chat.txt";
  a.click();
  URL.revokeObjectURL(a.href);
}
