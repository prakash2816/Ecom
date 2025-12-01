export function setToken(token: string, role: string) {
  localStorage.setItem("auth_token", token);
  localStorage.setItem("auth_role", role);
}

export function getToken(): string | null {
  return localStorage.getItem("auth_token");
}

export function getRole(): string | null {
  return localStorage.getItem("auth_role");
}

export function clearAuth() {
  localStorage.removeItem("auth_token");
  localStorage.removeItem("auth_role");
}

export async function register(payload: { email: string; password: string; name?: string; invite?: string }) {
  const res = await fetch(resolveUrl("/api/auth/register"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    let msg = "";
    try { msg = (await res.json()).error || ""; } catch (err) { void err; }
    if (res.status === 409) throw new Error("EMAIL_EXISTS");
    if (res.status === 503) throw new Error("BACKEND_UNAVAILABLE");
    throw new Error("REGISTRATION_FAILED");
  }
  const data = await res.json();
  setToken(data.token, data.role);
  await syncAccountStateAfterAuth();
  return data;
}

export async function login(payload: { email: string; password: string }) {
  const res = await fetch(resolveUrl("/api/auth/login"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    let msg = "";
    try { msg = (await res.json()).error || ""; } catch (err) { void err; }
    if (res.status === 401) throw new Error("INVALID_CREDENTIALS");
    if (res.status === 503) throw new Error("BACKEND_UNAVAILABLE");
    throw new Error("LOGIN_FAILED");
  }
  const data = await res.json();
  setToken(data.token, data.role);
  await syncAccountStateAfterAuth();
  return data;
}

export const apiBase = import.meta.env.VITE_API_BASE_URL || "";

function resolveUrl(input: RequestInfo | URL): RequestInfo | URL {
  if (typeof input === "string") {
    if (input.startsWith("/")) return `${apiBase}${input}`;
    return input;
  }
  return input;
}

export async function authFetch(input: RequestInfo | URL, init: RequestInit = {}) {
  const token = getToken();
  const headers = new Headers(init.headers || {});
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return fetch(resolveUrl(input), { ...init, headers });
}

import { syncCartFromServer } from "@/lib/cart";
import { syncWishlistFromServer } from "@/lib/wishlist";

async function syncAccountStateAfterAuth() {
  try {
    const token = getToken();
    if (!token) return;
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    const email = (payload?.email || "guest").toString();
    const rawCart = localStorage.getItem("cart_items_guest");
    const rawWish = localStorage.getItem("wishlist_items_guest");
    const cartItems = rawCart ? JSON.parse(rawCart) as Array<{ product: { id: string }; quantity: number }> : [];
    const wishItems = rawWish ? JSON.parse(rawWish) as Array<{ id: string }> : [];
    for (const it of cartItems) {
      const productId = it?.product?.id;
      const quantity = typeof it?.quantity === "number" ? it.quantity : 1;
      if (productId) {
        await authFetch("/api/cart", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ productId, quantity }) });
      }
    }
    for (const p of wishItems) {
      const productId = p?.id;
      if (productId) {
        await authFetch("/api/wishlist", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ productId }) });
      }
    }
    localStorage.removeItem("cart_items_guest");
    localStorage.removeItem("wishlist_items_guest");
    localStorage.removeItem(`cart_items_${email}`);
    localStorage.removeItem(`wishlist_items_${email}`);
    await syncCartFromServer();
    await syncWishlistFromServer();
  } catch {
    // no-op
  }
}

export function getEmail(): string | null {
  const token = getToken();
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    const email = payload?.email;
    return typeof email === "string" ? email : null;
  } catch {
    return null;
  }
}