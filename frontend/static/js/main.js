/* Team Cyber — Frontend Utilities */

// ── Auth guard ────────────────────────────────────────────────────────────────
function requireAuth() {
  if (!localStorage.getItem("tc_token")) {
    window.location.href = "/login";
  }
}

function logout() {
  localStorage.removeItem("tc_token");
  localStorage.removeItem("tc_user");
  window.location.href = "/login";
}

// ── API helpers ───────────────────────────────────────────────────────────────
function authHeaders() {
  const token = localStorage.getItem("tc_token");
  return {
    "Content-Type": "application/json",
    ...(token ? { "Authorization": `Bearer ${token}` } : {}),
  };
}

async function apiGet(url) {
  try {
    const res = await fetch(url, { headers: authHeaders() });
    if (res.status === 401) { logout(); return null; }
    return await res.json();
  } catch (e) {
    console.error("GET", url, e);
    return null;
  }
}

async function apiPost(url, body) {
  return fetch(url, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify(body),
  });
}

// ── Redirect authenticated users away from auth pages ────────────────────────
(function redirectIfAuthed() {
  const authPages = ["/login", "/register"];
  if (authPages.includes(window.location.pathname) && localStorage.getItem("tc_token")) {
    window.location.href = "/dashboard";
  }
})();
