/* Team Cyber — Frontend Utilities v2 */

// ── Auth ─────────────────────────────────────────────────────────
function requireAuth() {
  if (!localStorage.getItem("tc_token")) window.location.href = "/login";
}
function logout() {
  localStorage.removeItem("tc_token");
  localStorage.removeItem("tc_user");
  window.location.href = "/login";
}

// ── API ──────────────────────────────────────────────────────────
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
  return fetch(url, { method: "POST", headers: authHeaders(), body: JSON.stringify(body) });
}

// ── Toast notifications ───────────────────────────────────────────
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
    toast.style.animation = "fadeIn .3s ease reverse both";
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Animated counter ─────────────────────────────────────────────
function animateCounter(el, target, duration = 800) {
  const start = 0;
  const step = (timestamp) => {
    if (!start) start = timestamp;
    const elapsed = timestamp - start;
    const progress = Math.min(elapsed / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + (target - start) * ease);
    if (progress < 1) requestAnimationFrame(step);
    else el.textContent = target;
  };
  // Reset start inside closure
  let s = null;
  const fn = (timestamp) => {
    if (!s) s = timestamp;
    const elapsed = timestamp - s;
    const progress = Math.min(elapsed / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(target * ease);
    if (progress < 1) requestAnimationFrame(fn);
    else el.textContent = target;
  };
  requestAnimationFrame(fn);
}

// ── Fade-in on scroll ─────────────────────────────────────────────
function initScrollAnimations() {
  const obs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.style.animation = "fadeInUp .4s ease both";
        obs.unobserve(e.target);
      }
    });
  }, { threshold: 0.1 });
  document.querySelectorAll(".section-card, .stat-card, .form-card")
    .forEach(el => obs.observe(el));
}

// ── Severity utils ────────────────────────────────────────────────
function statusColor(s) {
  return { completed: "success", running: "warning", failed: "error", queued: "info" }[s] || "info";
}
function statusDot(s) {
  return `<span class="status-dot ${s}"></span>`;
}

// ── Redirect authed users from auth pages ─────────────────────────
(function () {
  const authPages = ["/login", "/register"];
  if (authPages.includes(window.location.pathname) && localStorage.getItem("tc_token")) {
    window.location.href = "/dashboard";
  }
})();

// ── Init on DOM ready ─────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initScrollAnimations();
  // Highlight active nav link
  document.querySelectorAll(".nav-link[href]").forEach(a => {
    if (a.getAttribute("href") === window.location.pathname) a.classList.add("active");
  });
});
