const $ = (selector) => document.querySelector(selector);
const sample = `From: "PayPal Security" <account-alert@paypa1-verify.net>\nSubject: URGENT: Your account will be permanently suspended\n\nWe detected unusual activity. You must verify your identity within 2 hours or your account will be closed.\n\nConfirm your account now: https://paypa1-secure-login.com/verify\n\nReply with your full name and one-time code if the link does not work.`;
const state = { history: [], activeScan: null };

function riskColor(score, level) { return score >= 70 ? "#ff6b57" : level === "Suspicious" || score >= 35 ? "#e2a438" : "#43d99f"; }
function escapeHtml(value) { const node = document.createElement("div"); node.textContent = value ?? ""; return node.innerHTML; }
function updateComposer() { const length = $("#content").value.length; $("#status").textContent = `${length.toLocaleString()} characters`; $("#status").classList.remove("error"); $("#analyzeButton").disabled = length < 20; $("#clearButton").classList.toggle("hidden", !length); }

function renderScan(scan) {
  state.activeScan = scan; $("#emptyResult").classList.add("hidden"); $("#filledResult").classList.remove("hidden");
  const risk = riskColor(scan.score, scan.level); $("#scoreRing").style.setProperty("--score", scan.score); $("#scoreRing").style.setProperty("--risk", risk); $("#scoreValue").textContent = scan.score; $("#riskLevel").textContent = scan.level; $("#riskLevel").style.color = risk; $("#summary").textContent = scan.summary; const warningCount = scan.findings.filter(f => f.points > 0).length; $("#signalSummary").textContent = `${warningCount} scored warning ${warningCount === 1 ? "sign" : "signs"} found across language, sender clues, and links.`; $("#findingCount").textContent = `(${scan.findings.length})`; $("#linkCount").textContent = `(${scan.links.length + (scan.senderChecks || []).length})`;
  $("#findings").innerHTML = scan.findings.map(f => `<article class="finding"><div class="finding-row"><span class="severity ${f.severity}">!</span><div class="finding-copy"><div class="finding-title"><h3>${escapeHtml(f.label)}</h3><span class="points">+${f.points}</span></div><p>${escapeHtml(f.detail)}</p>${f.evidence ? `<blockquote>“${escapeHtml(f.evidence)}”</blockquote>` : ""}</div></div></article>`).join("");
  const senderChecks = scan.senderChecks || [];
  const senderCards = senderChecks.map(sender => `<article class="link-card"><h3>${escapeHtml(sender.domain)} <span class="severity ${sender.status}">${sender.status === "warning" ? "Review" : "Unverified"}</span></h3><p>${escapeHtml(sender.note)}</p><p class="url">${escapeHtml(sender.email)}</p></article>`).join("");
  const linkCards = scan.links.map(link => `<article class="link-card"><h3>${escapeHtml(link.domain)} <span class="severity ${link.status}">${escapeHtml(link.status)}</span></h3><p>${escapeHtml(link.note)}</p><p class="url">${escapeHtml(link.url)}</p></article>`).join("");
  $("#linkChecks").innerHTML = senderCards + linkCards || `<div class="empty-history"><strong>No links or sender address detected</strong><p>The score is based on language clues. Sender and link safety cannot be confirmed from pasted text alone.</p></div>`;
}

async function analyze() {
  const content = $("#content").value.trim(); if (content.length < 20) return;
  const button = $("#analyzeButton"); button.disabled = true; button.textContent = "Checking…"; $("#status").classList.remove("error");
  try { const response = await fetch("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content }) }); const data = await response.json(); if (!response.ok) throw new Error(data.detail || "The scan could not be completed."); renderScan(data.scan); state.history = [data.scan, ...state.history.filter(item => item.id !== data.scan.id)].slice(0,20); renderHistory(); }
  catch (error) { $("#status").textContent = error.message; $("#status").classList.add("error"); }
  finally { button.disabled = false; button.textContent = "⌕ Analyze message"; }
}

function renderHistory() {
  $("#historyCount").textContent = `${state.history.length} saved`;
  $("#historyList").innerHTML = state.history.length ? state.history.map(item => `<button class="history-item" data-id="${item.id}"><span class="history-score" style="color:${riskColor(item.score, item.level)};background:${riskColor(item.score, item.level)}16">${item.score}</span><span class="history-copy"><strong>${escapeHtml(item.level)} · ${escapeHtml(item.kind)}</strong><span>${escapeHtml(item.content.replace(/\s+/g," "))}</span><small>${new Date(item.createdAt.replace(" ","T")+"Z").toLocaleString()}</small></span><span>›</span></button>`).join("") : `<div class="empty-history"><strong>No scans yet</strong><p>Your completed checks will appear here.</p></div>`;
  document.querySelectorAll(".history-item").forEach(button => button.addEventListener("click", () => { const item = state.history.find(scan => scan.id === Number(button.dataset.id)); if (!item) return; $("#content").value = item.content; updateComposer(); renderScan(item); showScanner(); }));
}
function showScanner() { $("#historyView").classList.add("hidden"); $("#scannerView").classList.remove("hidden"); $("#historyButton").innerHTML = "<span>◷</span> Scan history"; }
function showHistory() { $("#scannerView").classList.add("hidden"); $("#historyView").classList.remove("hidden"); $("#historyButton").innerHTML = "<span>‹</span> Back to scanner"; }

$("#content").addEventListener("input", updateComposer);
$("#sampleButton").addEventListener("click", () => { $("#content").value = sample; updateComposer(); });
$("#clearButton").addEventListener("click", () => { $("#content").value = ""; updateComposer(); $("#filledResult").classList.add("hidden"); $("#emptyResult").classList.remove("hidden"); });
$("#analyzeButton").addEventListener("click", analyze);
$("#historyButton").addEventListener("click", () => $("#historyView").classList.contains("hidden") ? showHistory() : showScanner());
document.querySelectorAll(".tab").forEach(tab => tab.addEventListener("click", () => { document.querySelectorAll(".tab").forEach(item => item.classList.remove("active")); tab.classList.add("active"); document.querySelectorAll(".tab-panel").forEach(panel => panel.classList.add("hidden")); document.getElementById(tab.dataset.tab).classList.remove("hidden"); }));

fetch("/api/scans").then(response => response.json()).then(data => { state.history = data.scans || []; renderHistory(); }).catch(() => renderHistory());
updateComposer();

if (new URLSearchParams(window.location.search).get("demo") === "1") {
  $("#content").value = sample;
  updateComposer();
  analyze();
}
