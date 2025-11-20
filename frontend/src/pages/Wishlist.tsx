import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import type { Product } from "@/types/product";
import { addToCart } from "@/lib/cart";
import { removeFromWishlist } from "@/lib/wishlist";
import { Heart } from "lucide-react";

const Wishlist = () => {
  const [items, setItems] = useState<Product[]>([]);
  useEffect(() => {
    try {
      const raw = localStorage.getItem("wishlist_items");
      setItems(raw ? (JSON.parse(raw) as Product[]) : []);
    } catch {
      setItems([]);
    }
  }, []);
  useEffect(() => {
    const handler = () => {
      try {
        const raw = localStorage.getItem("wishlist_items");
        setItems(raw ? (JSON.parse(raw) as Product[]) : []);
      } catch {
        setItems([]);
      }
    };
    window.addEventListener("wishlist:update", handler as EventListener);
    window.addEventListener("storage", handler);
    return () => {
      window.removeEventListener("wishlist:update", handler as EventListener);
      window.removeEventListener("storage", handler);
    };
  }, []);

  if (!items.length) {
    return (
      <div className="container px-4 py-16">
        <div className="max-w-2xl mx-auto text-center space-y-6">
          <h1 className="font-serif text-3xl md:text-4xl font-bold">My Wishlist</h1>
          <Heart className="h-16 w-16 mx-auto text-muted-foreground" />
          <p className="text-muted-foreground">Your wishlist is empty</p>
          <a href="/products"><Button size="lg">Browse Products</Button></a>
        </div>
      </div>
    );
  }

  return (
    <div className="container px-4 py-8">
      <h1 className="font-serif text-3xl md:text-4xl font-bold mb-8">My Wishlist</h1>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {items.map((p) => (
          <div key={p.id} className="border rounded-lg p-4 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <img src={p.images?.[0] ?? "/placeholder.svg"} alt={p.name} className="w-16 h-16 rounded-md object-cover" />
              <div>
                <p className="font-semibold">{p.name}</p>
                <p className="text-sm text-muted-foreground">₹{p.price.toLocaleString()}</p>
              </div>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => { addToCart(p, 1); }}>
                Add to Cart
              </Button>
              <Button variant="destructive" onClick={() => { removeFromWishlist(p.id); }}>
                Remove
              </Button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Wishlist;