import { Minus, Plus, Trash2 } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { useEffect, useState } from "react";
import type { CartItem } from "@/types/product";
import { getCart, updateQuantity, removeFromCart } from "@/lib/cart";

const Cart = () => {
  const [cartItems, setCartItems] = useState<CartItem[]>(getCart());
  useEffect(() => {
    const handler = () => setCartItems(getCart());
    window.addEventListener("cart:update", handler as EventListener);
    window.addEventListener("storage", handler);
    return () => {
      window.removeEventListener("cart:update", handler as EventListener);
      window.removeEventListener("storage", handler);
    };
  }, []);
  const subtotal: number = cartItems.reduce((sum, it) => sum + it.product.price * it.quantity, 0);
  const shipping: number = 0;
  const total: number = subtotal + shipping;

  if (cartItems.length === 0) {
    return (
      <div className="container px-4 py-16">
        <div className="max-w-2xl mx-auto text-center space-y-6">
          <h1 className="font-serif text-3xl md:text-4xl font-bold">Your Cart</h1>
          <p className="text-muted-foreground">Your cart is empty</p>
          <Link to="/products">
            <Button size="lg">Continue Shopping</Button>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="container px-4 py-8">
      <h1 className="font-serif text-3xl md:text-4xl font-bold mb-8">Shopping Cart</h1>

      <div className="grid lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-4">
          {cartItems.map(({ product, quantity }) => (
            <div key={product.id} className="flex items-center justify-between border rounded-lg p-4">
              <div className="flex items-center gap-4">
                <img src={product.images?.[0] ?? "/placeholder.svg"} alt={product.name} className="w-16 h-16 rounded-md object-cover" />
                <div>
                  <p className="font-semibold">{product.name}</p>
                  <p className="text-sm text-muted-foreground">₹{product.price.toLocaleString()}</p>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div className="flex items-center border rounded-lg">
                  <Button variant="ghost" size="sm" onClick={() => { updateQuantity(product.id, Math.max(1, quantity - 1)); }}>-</Button>
                  <span className="px-4 py-2">{quantity}</span>
                  <Button variant="ghost" size="sm" onClick={() => { updateQuantity(product.id, quantity + 1); }}>+</Button>
                </div>
                <Button variant="destructive" size="icon" onClick={() => { removeFromCart(product.id); }}>
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            </div>
          ))}
        </div>

        <div>
          <div className="bg-card rounded-lg p-6 sticky top-24">
            <h2 className="font-serif text-2xl font-bold mb-6">Order Summary</h2>
            
            <div className="space-y-4 mb-6">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Subtotal</span>
                <span className="font-semibold">₹{subtotal.toLocaleString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Shipping</span>
                <span className="font-semibold">
                  {shipping === 0 ? "FREE" : `₹${shipping.toLocaleString()}`}
                </span>
              </div>
              <Separator />
              <div className="flex justify-between text-lg">
                <span className="font-semibold">Total</span>
                <span className="font-bold">₹{total.toLocaleString()}</span>
              </div>
            </div>

            <div className="space-y-3 mb-6">
              <Input placeholder="Enter promo code" />
              <Button variant="outline" className="w-full">
                Apply Code
              </Button>
            </div>

            <Link to="/checkout">
              <Button size="lg" className="w-full">
                Proceed to Checkout
              </Button>
            </Link>

            <Link to="/products">
              <Button variant="ghost" className="w-full mt-3">
                Continue Shopping
              </Button>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Cart;
