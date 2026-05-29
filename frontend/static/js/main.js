/* Team Cyber — Frontend Utilities v3 | Enterprise Edition */

// ── Auth ──────────────────────────────────────────────────────────
function requireAuth() {
  if (!localStorage.getItem("tc_token")) window.location.href = "/login";
}
function logout() {
  localStorage.removeItem("tc_token");
  localStorage.removeItem("tc_user");
  window.location.href = "/login";
}

// ── API ───────────────────────────────────────────────────────────
function authHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${localStorage.getItem("tc_token") || ""}`,
  };
}
async function apiGet(url) {
  try {
    const res = await fetch(url, { headers: authHeaders() });
    if (res.status === 401) { logout(); return null; }
    return await res.json();
  } catch (e) { console.error("GET", url, e); return null; }
}
async function apiPost(url, body) {
  return fetch(url, {
    method: "POST", headers: authHeaders(), body: JSON.stringify(body),
  });
}

// ── Toast ─────────────────────────────────────────────────────────
function showToast(message, type = "info", duration = 3500) {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    container.className = "toast-container";
    document.body.appendChild(container);
  }
  const icons = { success: "✓", error: "✕", info: "ℹ" };
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span style="font-size:15px">${icons[type]||"•"}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = "fadeOut .3s ease both";
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Animated counter ──────────────────────────────────────────────
function animateCounter(el, target, duration = 900) {
  if (!el) return;
  let start = null;
  const fn = (ts) => {
    if (!start) start = ts;
    const progress = Math.min((ts - start) / duration, 1);
    const ease     = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(target * ease);
    if (progress < 1) requestAnimationFrame(fn);
    else el.textContent = target;
  };
  requestAnimationFrame(fn);
}

// ── Severity bar chart (pure CSS) ────────────────────────────────
function renderSevBar(el, counts) {
  const total = (counts.critical||0) + (counts.high||0) + (counts.medium||0) + (counts.low||0);
  if (!total || !el) { el && (el.innerHTML = ""); return; }
  const pct = (n) => ((n / total) * 100).toFixed(1);
  el.innerHTML = `
    <div class="sev-bar" title="${total} total findings">
      ${counts.critical ? `<div class="sev-bar-seg critical" style="width:${pct(counts.critical)}%" title="${counts.critical} Critical"></div>` : ""}
      ${counts.high     ? `<div class="sev-bar-seg high"     style="width:${pct(counts.high)}%"     title="${counts.high} High"></div>` : ""}
      ${counts.medium   ? `<div class="sev-bar-seg medium"   style="width:${pct(counts.medium)}%"   title="${counts.medium} Medium"></div>` : ""}
      ${counts.low      ? `<div class="sev-bar-seg low"       style="width:${pct(counts.low)}%"     title="${counts.low} Low"></div>` : ""}
    </div>`;
}

// ── Donut chart (SVG) ─────────────────────────────────────────────
function renderDonut(svgEl, segments, size = 100, strokeW = 14) {
  if (!svgEl) return;
  const r      = (size - strokeW) / 2;
  const cx     = size / 2;
  const cy     = size / 2;
  const circum = 2 * Math.PI * r;
  const total  = segments.reduce((s, seg) => s + seg.value, 0);
  if (!total) return;

  let offset = 0;
  svgEl.setAttribute("viewBox", `0 0 ${size} ${size}`);
  svgEl.setAttribute("width",  size);
  svgEl.setAttribute("height", size);
  svgEl.innerHTML = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none"
    stroke="rgba(255,255,255,0.05)" stroke-width="${strokeW}"/>`;

  for (const seg of segments) {
    if (!seg.value) continue;
    const dash = (seg.value / total) * circum;
    const gap  = circum - dash;
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", cx);
    circle.setAttribute("cy", cy);
    circle.setAttribute("r",  r);
    circle.setAttribute("fill", "none");
    circle.setAttribute("stroke", seg.color);
    circle.setAttribute("stroke-width", strokeW);
    circle.setAttribute("stroke-linecap", "round");
    circle.setAttribute("stroke-dasharray", `${dash} ${gap}`);
    circle.setAttribute("stroke-dashoffset", circum * 0.25 - offset * (circum / total) * 0 - circum * 0.25);
    circle.style.transform = `rotate(${(offset / total) * 360 - 90}deg)`;
    circle.style.transformOrigin = `${cx}px ${cy}px`;
    circle.style.transition = "stroke-dasharray 1s ease";
    svgEl.appendChild(circle);
    offset += seg.value;
  }
}

// ── Risk score (0-100, lower is better) ──────────────────────────
function calcRiskScore(counts) {
  const weights = { critical: 40, high: 15, medium: 5, low: 1 };
  const raw = (counts.critical||0) * weights.critical
            + (counts.high||0)     * weights.high
            + (counts.medium||0)   * weights.medium
            + (counts.low||0)      * weights.low;
  return Math.min(100, raw);
}

function riskLabel(score) {
  if (score === 0)   return { label: "Secure",   color: "var(--green-dim)" };
  if (score < 20)    return { label: "Low Risk",  color: "var(--low)" };
  if (score < 50)    return { label: "Medium Risk", color: "var(--medium)" };
  if (score < 80)    return { label: "High Risk",  color: "var(--high)" };
  return              { label: "Critical",    color: "var(--critical)" };
}

// ── Render risk ring ──────────────────────────────────────────────
function renderRiskRing(wrapEl, counts) {
  if (!wrapEl) return;
  const score = calcRiskScore(counts);
  const { label, color } = riskLabel(score);
  const r      = 44;
  const circum = 2 * Math.PI * r;
  const fill   = (score / 100) * circum;
  wrapEl.innerHTML = `
    <div class="risk-ring">
      <svg viewBox="0 0 100 100" width="100" height="100">
        <circle class="track" cx="50" cy="50" r="${r}"/>
        <circle class="fill" cx="50" cy="50" r="${r}"
          stroke="${color}"
          stroke-dasharray="${fill} ${circum - fill}"
          stroke-dashoffset="${circum * 0.25}"/>
      </svg>
      <div class="label">
        <span class="score" style="color:${color}">${score}</span>
        <span class="sub">RISK</span>
      </div>
    </div>`;
}

// ── Team badge helper ─────────────────────────────────────────────
function teamBadge(team) {
  if (team === "red")  return `<span class="badge badge-red-team">⚔ Red Team</span>`;
  if (team === "blue") return `<span class="badge badge-blue-team">🛡 Blue Team</span>`;
  return "";
}

// ── Source type badge ─────────────────────────────────────────────
function sourceBadge(type) {
  const map = {
    zip:    { icon: "📦", cls: "badge-tool",      label: "ZIP" },
    github: { icon: "🐙", cls: "badge-info",      label: "GitHub" },
    url:    { icon: "🌐", cls: "badge-url",        label: "Live URL" },
  };
  const b = map[type] || { icon: "📄", cls: "badge-tool", label: type.toUpperCase() };
  return `<span class="badge ${b.cls}">${b.icon} ${b.label}</span>`;
}

// ── Severity utils ────────────────────────────────────────────────
function statusColor(s) {
  return { completed:"success", running:"warning", failed:"error", queued:"info" }[s] || "info";
}
function statusDot(s) { return `<span class="status-dot ${s}"></span>`; }

// ── Scroll animations ─────────────────────────────────────────────
function initScrollAnimations() {
  const obs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.style.animation = "fadeInUp .4s ease both";
        obs.unobserve(e.target);
      }
    });
  }, { threshold: 0.08 });
  document.querySelectorAll(".section-card, .stat-card, .form-card, .chart-card")
    .forEach(el => obs.observe(el));
}

// ── Load user info into navbar ────────────────────────────────────
function initNavUser() {
  const u = localStorage.getItem("tc_user");
  const el = document.getElementById("nav-username");
  const av = document.getElementById("nav-avatar");
  if (el && u) {
    el.textContent = u;
    if (av) av.textContent = u.charAt(0).toUpperCase();
  }
}

// ── Auth page redirect guard ──────────────────────────────────────
(function () {
  const authPages = ["/login", "/register"];
  if (authPages.includes(window.location.pathname) && localStorage.getItem("tc_token")) {
    window.location.href = "/dashboard";
  }
})();

// ── DOM Ready ─────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initScrollAnimations();
  initNavUser();
  // Highlight active nav link
  document.querySelectorAll(".nav-link[href]").forEach(a => {
    const path = a.getAttribute("href");
    if (window.location.pathname === path ||
        (path !== "/" && window.location.pathname.startsWith(path))) {
      a.classList.add("active");
    }
  });
});

// ── escapeHtml ────────────────────────────────────────────────────
function escHtml(s) {
  return (s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
