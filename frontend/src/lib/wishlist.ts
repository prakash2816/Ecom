import type { Product } from "@/types/product";
import { authFetch, getToken } from "@/lib/auth";

const KEY = "wishlist_items";

function read(): Product[] {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Product[]) : [];
  } catch {
    return [];
  }
}

function write(items: Product[]) {
  localStorage.setItem(KEY, JSON.stringify(items));
  window.dispatchEvent(new Event("wishlist:update"));
}

export function getWishlist(): Product[] {
  return read();
}

export function isWishlisted(id: string): boolean {
  return read().some((p) => p.id === id);
}

export function toggleWishlist(product: Product) {
  const items = read();
  const idx = items.findIndex((p) => p.id === product.id);
  if (idx >= 0) {
    items.splice(idx, 1);
  } else {
    items.push(product);
  }
  write(items);
  const token = getToken();
  if (token) {
    const exists = idx >= 0;
    if (exists) {
      authFetch(`/api/wishlist?productId=${encodeURIComponent(product.id)}`, { method: "DELETE" })
        .then(() => { syncWishlistFromServer().catch(() => {}); })
        .catch(() => {});
    } else {
      authFetch("/api/wishlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ productId: product.id }),
      }).then(() => { syncWishlistFromServer().catch(() => {}); }).catch(() => {});
    }
  }
}

export function removeFromWishlist(id: string) {
  write(read().filter((p) => p.id !== id));
  const token = getToken();
  if (token) {
    authFetch(`/api/wishlist?productId=${encodeURIComponent(id)}`, { method: "DELETE" })
      .then(() => { syncWishlistFromServer().catch(() => {}); })
      .catch(() => {});
  }
}

export function clearWishlist() {
  write([]);
  const token = getToken();
  if (token) {
    authFetch(`/api/wishlist?all=1`, { method: "DELETE" })
      .then(() => { syncWishlistFromServer().catch(() => {}); })
      .catch(() => {});
  }
}

export async function syncWishlistFromServer() {
  const token = getToken();
  if (!token) return;
  const res = await authFetch("/api/wishlist");
  if (!res.ok) return;
  const data = (await res.json()) as Product[];
  write(data);
}