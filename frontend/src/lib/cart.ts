import type { Product, CartItem } from "@/types/product";
import { authFetch, getToken } from "@/lib/auth";

const KEY = "cart_items";

function read(): CartItem[] {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as CartItem[]) : [];
  } catch {
    return [];
  }
}

function write(items: CartItem[]) {
  localStorage.setItem(KEY, JSON.stringify(items));
  window.dispatchEvent(new Event("cart:update"));
}

export function getCart(): CartItem[] {
  return read();
}

export function getCount(): number {
  return read().reduce((sum, it) => sum + it.quantity, 0);
}

export function addToCart(product: Product, quantity = 1) {
  const items = read();
  const idx = items.findIndex((i) => i.product.id === product.id);
  if (idx >= 0) {
    items[idx].quantity = Math.min((items[idx].quantity || 0) + quantity, product.stock);
  } else {
    items.push({ product, quantity });
  }
  write(items);
  const token = getToken();
  if (token) {
    const q = items.find((i) => i.product.id === product.id)?.quantity || quantity;
    authFetch("/api/cart", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ productId: product.id, quantity: q }),
    }).then(() => {
      syncCartFromServer().catch(() => {});
    }).catch(() => {});
  }
}

export function updateQuantity(productId: string, quantity: number) {
  const items = read();
  const idx = items.findIndex((i) => i.product.id === productId);
  if (idx >= 0) {
    items[idx].quantity = Math.max(1, quantity);
    write(items);
    const token = getToken();
    if (token) {
      authFetch("/api/cart", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ productId, quantity: Math.max(1, quantity) }),
      }).then(() => {
        syncCartFromServer().catch(() => {});
      }).catch(() => {});
    }
  }
}

export function removeFromCart(productId: string) {
  const items = read().filter((i) => i.product.id !== productId);
  write(items);
  const token = getToken();
  if (token) {
    authFetch(`/api/cart?productId=${encodeURIComponent(productId)}`, { method: "DELETE" })
      .then(() => { syncCartFromServer().catch(() => {}); })
      .catch(() => {});
  }
}

export function clearCart() {
  write([]);
  const token = getToken();
  if (token) {
    authFetch(`/api/cart?all=1`, { method: "DELETE" })
      .then(() => { syncCartFromServer().catch(() => {}); })
      .catch(() => {});
  }
}

export async function syncCartFromServer() {
  const token = getToken();
  if (!token) return;
  const res = await authFetch("/api/cart");
  if (!res.ok) return;
  const data = (await res.json()) as CartItem[];
  write(data);
}