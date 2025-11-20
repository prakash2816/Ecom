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
  const res = await fetch("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error("Registration failed");
  const data = await res.json();
  setToken(data.token, data.role);
  await syncAccountStateAfterAuth();
  return data;
}

export async function login(payload: { email: string; password: string }) {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error("Login failed");
  const data = await res.json();
  setToken(data.token, data.role);
  await syncAccountStateAfterAuth();
  return data;
}

export async function authFetch(input: RequestInfo | URL, init: RequestInit = {}) {
  const token = getToken();
  const headers = new Headers(init.headers || {});
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return fetch(input, { ...init, headers });
}

import { syncCartFromServer } from "@/lib/cart";
import { syncWishlistFromServer } from "@/lib/wishlist";

async function syncAccountStateAfterAuth() {
  try {
    const token = getToken();
    if (!token) return;
    const rawCart = localStorage.getItem("cart_items");
    const rawWish = localStorage.getItem("wishlist_items");
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
    await syncCartFromServer();
    await syncWishlistFromServer();
  } catch {
    // no-op
  }
}