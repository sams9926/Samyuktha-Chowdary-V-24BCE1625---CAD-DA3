async function api(path, opts = {}) {
  const token = localStorage.getItem("token");

  const headers = {};

  if (!(opts.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  if (token) {
    headers["Authorization"] = "Bearer " + token;
  }

  const res = await fetch("/api" + path, {
    ...opts,
    headers
  });

  // Expired/invalid token -> back to login
  // (but not for the login call itself)
  if (res.status === 401 && !path.startsWith("/login")) {
    localStorage.removeItem("token");
    location.href = "/index.html";
    return;
  }

  let data = null;

  try {
    data = await res.json();
  } catch (e) {}

  if (!res.ok) {
    throw new Error(
      (data && data.detail) || "Request failed"
    );
  }

  return data;
}