import { ReactNode, useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { ShoppingCart, User, Search, Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetTrigger,
} from "@/components/ui/sheet";
import { getRole, getToken, clearAuth } from "@/lib/auth";
import { toast } from "@/components/ui/sonner";
import { clearCart, getCount, syncCartFromServer } from "@/lib/cart";
import { clearWishlist, syncWishlistFromServer } from "@/lib/wishlist";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenuLabel } from "@/components/ui/dropdown-menu";
import { getEmail } from "@/lib/auth";

interface LayoutProps {
  children: ReactNode;
}

const Layout = ({ children }: LayoutProps) => {
  const [role, setRole] = useState<string | null>(null);
  const [cartCount, setCartCount] = useState(0);
  const [authed, setAuthed] = useState<boolean>(!!getToken());
  const [adminOrdersCount, setAdminOrdersCount] = useState<number>(0);
  const location = useLocation();
  const navigate = useNavigate();
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  useEffect(() => {
    setRole(getRole());
    setCartCount(getCount());
    setAuthed(!!getToken());
    const token = getToken();
    if (token) {
      Promise.all([syncCartFromServer(), syncWishlistFromServer()]).then(() => {
        setCartCount(getCount());
      }).catch(() => {});
    }
    (async () => {
      try {
        const r = getRole();
        if (r === "admin") {
          const res = await authFetch("/api/admin/orders");
          if (res.ok) {
            const list: Array<{ createdAt?: number }> = await res.json();
            const lastSeen = Number(localStorage.getItem("admin_last_seen_orders_ts") || 0);
            const unseen = Array.isArray(list) ? list.filter((o) => Number(o.createdAt || 0) > lastSeen).length : 0;
            const onOrdersPage = location.pathname.startsWith("/admin/orders");
            if (onOrdersPage) {
              localStorage.setItem("admin_last_seen_orders_ts", String(Date.now()));
              setAdminOrdersCount(0);
            } else {
              setAdminOrdersCount(unseen);
            }
          }
        } else {
          setAdminOrdersCount(0);
        }
      } catch { setAdminOrdersCount(0); }
    })();
    const interval = setInterval(async () => {
      try {
        const r = getRole();
        const token2 = getToken();
        if (r !== "admin") return;
        const res = await authFetch("/api/admin/orders");
        if (!res.ok) return;
        const list: Array<{ createdAt?: number }> = await res.json();
        const lastSeen = Number(localStorage.getItem("admin_last_seen_orders_ts") || 0);
        const unseen = Array.isArray(list) ? list.filter((o) => Number(o.createdAt || 0) > lastSeen).length : 0;
        const prev = adminOrdersCount;
        setAdminOrdersCount(unseen);
        if (unseen > prev) toast(`${unseen} new order${unseen > 1 ? "s" : ""}`);
      } catch (e) { void e; }
    }, 30000);
    return () => clearInterval(interval);
  }, [location.pathname, adminOrdersCount]);
  useEffect(() => {
    const handler = () => {
      setRole(getRole());
      setCartCount(getCount());
      setAuthed(!!getToken());
    };
    window.addEventListener("storage", handler);
    window.addEventListener("cart:update", handler as EventListener);
    window.addEventListener("orders:update", handler as EventListener);
    return () => {
      window.removeEventListener("storage", handler);
      window.removeEventListener("orders:update", handler as EventListener);
    };
  }, []);
  return (
    <div className="min-h-screen flex flex-col">
      <header className="sticky top-0 z-50 w-full border-b bg-card/95 backdrop-blur supports-[backdrop-filter]:bg-card/60">
        <div className="container flex h-16 items-center justify-between px-4">
          <div className="flex items-center gap-6">
            <Sheet>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon" className="md:hidden">
                  <Menu className="h-5 w-5" />
                </Button>
              </SheetTrigger>
              <SheetContent side="left">
                <nav className="flex flex-col gap-4">
                  <Link to="/" className="text-lg font-medium hover:text-primary">
                    Home
                  </Link>
                  <Link to="/products" className="text-lg font-medium hover:text-primary">
                    Shop
                  </Link>
                  <Link to="/products?category=new" className="text-lg font-medium hover:text-primary">
                    New Arrivals
                  </Link>
                  <Link to="/products?category=sale" className="text-lg font-medium hover:text-primary">
                    Sale
                  </Link>
                </nav>
              </SheetContent>
            </Sheet>

            <Link to="/" className="flex items-center">
              <span className="font-serif text-2xl font-bold text-primary">
                Saree Elegance
              </span>
            </Link>

            {role !== "admin" && (
              <nav className="hidden md:flex items-center gap-6">
                <Link to="/products" className="text-sm font-medium hover:text-primary transition-colors">
                  Shop
                </Link>
                <Link to="/products?category=new" className="text-sm font-medium hover:text-primary transition-colors">
                  New Arrivals
                </Link>
                <Link to="/products?category=sale" className="text-sm font-medium hover:text-primary transition-colors">
                  Sale
                </Link>
              </nav>
            )}
          </div>

          <div className="flex items-center gap-2">
            {role !== "admin" && (
              <div className="hidden md:flex items-center gap-2">
                <Button variant="ghost" size="icon" onClick={() => setSearchOpen((s) => !s)}>
                  <Search className="h-5 w-5" />
                </Button>
                {searchOpen && (
                  <Input
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") navigate(`/products?query=${encodeURIComponent(searchTerm)}`);
                    }}
                    placeholder="Type to search"
                    className="w-[220px]"
                  />
                )}
              </div>
            )}
            {role === "admin" && (
              <>
                <Link to="/admin">
                  <Button variant="ghost">Admin</Button>
                </Link>
                <Link to="/admin/orders">
                  <Button variant="ghost" className="relative">
                    Orders
                    {adminOrdersCount > 0 ? (
                      <span className="absolute -top-1 -right-1 h-5 min-w-5 rounded-full bg-destructive text-destructive-foreground text-[10px] px-1 flex items-center justify-center">
                        {adminOrdersCount}
                      </span>
                    ) : null}
                  </Button>
                </Link>
              </>
            )}
            {role === "admin" ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon">
                    <User className="h-5 w-5" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent className="p-1">
                  <DropdownMenuLabel>{getEmail() || "Admin"}</DropdownMenuLabel>
                  <DropdownMenuItem onSelect={() => { clearAuth(); clearCart(); clearWishlist(); navigate("/login"); }}>Logout</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : authed ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon">
                    <User className="h-5 w-5" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent className="p-1">
                  <DropdownMenuItem onSelect={() => navigate("/account")}>My Account</DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => navigate("/wishlist")}>Wishlist</DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => navigate("/orders")}>Orders</DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => { clearAuth(); clearCart(); clearWishlist(); navigate("/login"); }}>Logout</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : (
              <Link to="/login">
                <Button variant="ghost" size="icon">
                  <User className="h-5 w-5" />
                </Button>
              </Link>
            )}
            {role !== "admin" && (
              <Link to="/cart">
                <Button variant="ghost" size="icon" className="relative">
                  <ShoppingCart className="h-5 w-5" />
                  <span className="absolute -top-1 -right-1 h-5 w-5 rounded-full bg-primary text-primary-foreground text-xs flex items-center justify-center">
                    {cartCount}
                  </span>
                </Button>
              </Link>
            )}
          </div>
        </div>
      </header>

      <main className="flex-1">{children}</main>

      <footer className="border-t bg-card">
        <div className="container px-4 py-12">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div>
              <h3 className="font-serif text-lg font-semibold mb-4">Saree Elegance</h3>
              <p className="text-sm text-muted-foreground">
                Premium handcrafted sarees for every occasion
              </p>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Shop</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><Link to="/products" className="hover:text-foreground">All Sarees</Link></li>
                <li><Link to="/products?category=silk" className="hover:text-foreground">Silk Collection</Link></li>
                <li><Link to="/products?category=designer" className="hover:text-foreground">Designer Range</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Support</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><Link to="/contact" className="hover:text-foreground">Contact Us</Link></li>
                <li><Link to="/shipping" className="hover:text-foreground">Shipping Info</Link></li>
                <li><Link to="/returns" className="hover:text-foreground">Returns</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Follow Us</h4>
              <div className="flex gap-4">
                <a href="#" className="text-muted-foreground hover:text-foreground">Instagram</a>
                <a href="#" className="text-muted-foreground hover:text-foreground">Facebook</a>
              </div>
            </div>
          </div>
          <div className="mt-8 pt-8 border-t text-center text-sm text-muted-foreground">
            © 2024 Saree Elegance. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Layout;
