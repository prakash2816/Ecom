import { Link } from "react-router-dom";
import HeroCarousel from "@/components/HeroCarousel";
import ProductCard from "@/components/ProductCard";
import { categories, leninSubcategories } from "@/data/products";
import { useQuery } from "@tanstack/react-query";
import { getProducts } from "@/lib/api";
import type { Product } from "@/types/product";
import { Button } from "@/components/ui/button";
import { useQuery as useQueryRQ } from "@tanstack/react-query";
import { apiBase } from "@/lib/auth";

const Home = () => {
  const { data } = useQuery<Product[]>({ queryKey: ["products"], queryFn: getProducts });
  const { data: banners = [] } = useQueryRQ<string[]>({
    queryKey: ["banners"],
    queryFn: async () => {
      const res = await fetch(`${apiBase}/api/banners`);
      return res.json();
    },
  });
  const { data: bestsellers = [] } = useQueryRQ<Product[]>({
    queryKey: ["bestsellers"],
    queryFn: async () => {
      const res = await fetch(`${apiBase}/api/bestsellers`, { headers: {} });
      return res.json();
    },
  });
  return (
    <div>
      <HeroCarousel />

      {/* Categories Tiles */}
      <CategoryTilesSection />

      {/* Featured Products */}
      <section className="py-16">
        <div className="container px-4">
          <div className="flex items-center justify-between mb-8">
            <h2 className="font-serif text-3xl md:text-4xl font-bold">
              Featured Collection
            </h2>
            <Link to="/products">
              <Button variant="outline">View All</Button>
            </Link>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
            {data?.slice(0, 5).map((product) => (
              <ProductCard key={product.id} product={product} compact />
            ))}
          </div>
        </div>
      </section>

      {banners.length > 0 && (
        <section className="py-12">
          <div className="container px-4">
            <div className="rounded-lg overflow-hidden border bg-card">
              <img src={banners[0]} alt="Banner" className="w-full h-[260px] md:h-[320px] object-cover" />
            </div>
          </div>
        </section>
      )}

      {bestsellers.length > 0 && (
        <section className="py-16">
          <div className="container px-4">
            <div className="flex items-center justify-between mb-8">
              <h2 className="font-serif text-3xl md:text-4xl font-bold">Bestsellers</h2>
              <Link to="/products">
                <Button variant="outline">View All</Button>
              </Link>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
              {bestsellers.slice(0, 5).map((product) => (
                <ProductCard key={product.id} product={product} compact />
              ))}
            </div>
          </div>
        </section>
      )}

      {/* Editorial Section */}
      <section className="py-16 bg-primary text-primary-foreground">
        <div className="container px-4">
          <div className="max-w-3xl mx-auto text-center space-y-6">
            <h2 className="font-serif text-3xl md:text-4xl font-bold">
              Crafted with Tradition
            </h2>
            <p className="text-lg opacity-90">
              Each saree in our collection is a masterpiece, handwoven by skilled artisans
              using time-honored techniques passed down through generations. Experience the
              perfect blend of heritage and contemporary elegance.
            </p>
            <Button size="lg" variant="secondary" className="mt-4">
              Learn Our Story
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Home;

function CategoryTilesSection() {
  const { data: tiles = [] } = useQueryRQ<{ category: string; image: string; position?: number }[]>({
    queryKey: ["category-tiles"],
    queryFn: async () => {
      const res = await fetch(`${apiBase}/api/category-tiles`);
      return res.json();
    },
  });
  if (!tiles.length) return null;
  return (
    <section className="py-16 bg-background">
      <div className="container px-4">
        <h2 className="font-serif text-3xl md:text-4xl font-bold mb-8">Shop by Category</h2>
        <div className="md:hidden -mx-4 px-4 overflow-x-auto snap-x snap-mandatory">
          <div className="flex gap-3">
            {tiles.slice(0,6).map((t) => (
              <Link key={t.category} to={`/products?category=${encodeURIComponent(t.category.toLowerCase())}`} className="group snap-start">
                <div className="rounded-lg overflow-hidden border bg-card w-40">
                  <div className="aspect-[2/3] w-full">
                    <img src={t.image || "/placeholder.svg"} alt={t.category} className="w-full h-full object-cover" />
                  </div>
                  <div className="p-2">
                    <div className="text-sm font-semibold truncate">{t.category}</div>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </div>
        <div className="hidden md:grid grid-cols-6 gap-4">
          {tiles.slice(0,6).map((t) => (
            <Link key={t.category} to={`/products?category=${encodeURIComponent(t.category.toLowerCase())}`} className="group">
              <div className="rounded-lg overflow-hidden border bg-card">
                <div className="h-[200px] w-full">
                  <img src={t.image || "/placeholder.svg"} alt={t.category} className="w-full h-full object-cover" />
                </div>
                <div className="p-2">
                  <div className="text-sm font-semibold truncate">{t.category}</div>
                </div>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}
