import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Heart, Share2, ShoppingCart, Star, ChevronLeft, ChevronRight } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { getProduct, getProducts } from "@/lib/api";
import type { Product } from "@/types/product";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import ProductCard from "@/components/ProductCard";
import { addToCart } from "@/lib/cart";
import { toggleWishlist, isWishlisted } from "@/lib/wishlist";

const ProductDetail = () => {
  const { id } = useParams();
  const { data: product } = useQuery<Product | undefined>({
    queryKey: ["product", id],
    queryFn: () => (id ? getProduct(id) : Promise.resolve(undefined)),
  });
  const { data: all } = useQuery<Product[]>({ queryKey: ["products"], queryFn: getProducts });
  const [selectedImage, setSelectedImage] = useState(0);
  const [quantity, setQuantity] = useState(1);
  const [pincode, setPincode] = useState("");
  const [deliveryMsg, setDeliveryMsg] = useState<string | null>(null);
  const [wish, setWish] = useState(false);

  useEffect(() => {
    window.scrollTo(0, 0);
    setWish(product ? isWishlisted(product.id) : false);
  }, [id]);

  if (!product) {
    return (
      <div className="container px-4 py-16 text-center">
        <h1 className="text-2xl font-bold mb-4">Product not found</h1>
        <Link to="/products">
          <Button>Back to Shop</Button>
        </Link>
      </div>
    );
  }

  const relatedProducts = (all || []).filter((p) => p.id !== id).slice(0, 4);
  const images = (product?.images || []).filter((u) => typeof u === "string" && u && !u.startsWith("blob:"));

  return (
    <div>
      <div className="container px-4 py-8">
        <div className="grid md:grid-cols-[88px_minmax(0,520px)_1fr] gap-4 mb-16">
          <div className="hidden md:flex md:flex-col gap-1">
            {images.map((image, index) => (
              <button
                key={index}
                onClick={() => setSelectedImage(index)}
                className={`relative w-full aspect-square rounded-md overflow-hidden border-2 ${
                  selectedImage === index ? "border-primary" : "border-transparent"
                }`}
              >
                <img
                  src={image || "/placeholder.svg"}
                  alt={`${product.name} ${index + 1}`}
                  className="w-full h-full object-cover"
                />
              </button>
            ))}
          </div>

          <div>
            <div className="relative mb-4 aspect-square max-w-[520px] bg-card rounded-lg overflow-hidden">
              <img
                src={(images && images[selectedImage]) || "/placeholder.svg"}
                alt={product.name}
                className="w-full h-full object-cover"
              />
              {product.discount && (
                <Badge className="absolute top-4 left-4 bg-primary text-primary-foreground">
                  {product.discount}% OFF
                </Badge>
              )}
            </div>

            {images.length > 1 && (
              <div className="md:hidden flex gap-2 overflow-x-auto pb-2">
                {images.map((image, index) => (
                  <button
                    key={index}
                    onClick={() => setSelectedImage(index)}
                    className={`flex-shrink-0 w-16 h-16 rounded-md overflow-hidden border-2 ${
                      selectedImage === index ? "border-primary" : "border-transparent"
                    }`}
                  >
                    <img
                      src={image || "/placeholder.svg"}
                      alt={`${product.name} ${index + 1}`}
                      className="w-full h-full object-cover"
                    />
                  </button>
                ))}
              </div>
            )}
            </div>

          {/* Product Info */}
          <div className="space-y-6">
            <div>
              <h1 className="font-serif text-3xl md:text-4xl font-bold mb-2">
                {product.name}
              </h1>
              <p className="text-muted-foreground">{product.brand}</p>
            </div>

            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1">
                {[...Array(5)].map((_, i) => (
                  <Star
                    key={i}
                    className={`h-5 w-5 ${
                      i < Math.floor(product.rating)
                        ? "fill-accent text-accent"
                        : "text-muted"
                    }`}
                  />
                ))}
              </div>
              <span className="text-sm text-muted-foreground">
                {product.rating} ({product.reviews.length} reviews)
              </span>
            </div>

            <div className="flex items-baseline gap-3">
              <span className="text-3xl font-bold">
                ₹{product.price.toLocaleString()}
              </span>
              {product.originalPrice && (
                <span className="text-xl text-muted-foreground line-through">
                  ₹{product.originalPrice.toLocaleString()}
                </span>
              )}
              {(product.saveAmount ?? (product.originalPrice ? product.originalPrice - product.price : 0)) > 0 && (
                <Badge variant="secondary">Save ₹{((product.saveAmount ?? (product.originalPrice ? product.originalPrice - product.price : 0))).toLocaleString()}</Badge>
              )}
            </div>

            <div className="space-y-4">
              <h3 className="font-semibold">Delivery Date Check</h3>
              <div className="flex gap-2 max-w-sm">
                <Input
                  placeholder="Enter Pincode"
                  value={pincode}
                  onChange={(e) => setPincode(e.target.value)}
                />
                <Button
                  variant="outline"
                  onClick={() => {
                    const ok = /^\d{6}$/.test(pincode);
                    setDeliveryMsg(ok ? "Delivery available" : "Enter 6-digit pincode");
                  }}
                >
                  Check
                </Button>
              </div>
              {deliveryMsg && <p className="text-sm text-muted-foreground">{deliveryMsg}</p>}
            </div>

            <div className="space-y-4">
              {Array.isArray(product.colorLinks) && product.colorLinks.length > 0 && (
                <div>
                  <h3 className="font-semibold mb-2">Color</h3>
                  <div className="flex gap-2">
                    {product.colorLinks.map((c) => (
                      <a key={c.image + c.url} href={c.url} className="w-12 h-12 rounded-md overflow-hidden border bg-card flex items-center justify-center">
                        <img src={c.image || "/placeholder.svg"} alt="color" className="w-full h-full object-cover" />
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center gap-4">
              <div className="flex items-center border rounded-lg">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setQuantity(Math.max(1, quantity - 1))}
                >
                  -
                </Button>
                <span className="px-4 py-2">{quantity}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setQuantity(Math.min(product.stock, quantity + 1))}
                >
                  +
                </Button>
              </div>
              <span className="text-sm text-muted-foreground">
                {product.stock} in stock
              </span>
            </div>

            <div className="flex gap-3">
              <Button size="lg" className="flex-1" onClick={() => addToCart(product, quantity)}>
                <ShoppingCart className="h-5 w-5 mr-2" />
                Add to Cart
              </Button>
              <Button size="lg" variant="outline" onClick={() => { toggleWishlist(product); setWish(!wish); }}>
                <Heart className={`h-5 w-5 ${wish ? "text-primary" : ""}`} />
              </Button>
              <Button size="lg" variant="outline">
                <Share2 className="h-5 w-5" />
              </Button>
            </div>

            <Button size="lg" variant="secondary" className="w-full">
              Buy Now
            </Button>

            
          </div>
        </div>

        {/* Product Details Tabs */}
        <Tabs defaultValue="details" className="mb-16">
          <TabsList className="w-full justify-start">
            <TabsTrigger value="details">Details</TabsTrigger>
            <TabsTrigger value="care">Care Instructions</TabsTrigger>
            <TabsTrigger value="reviews">Reviews ({product.reviews.length})</TabsTrigger>
          </TabsList>
          <TabsContent value="details" className="mt-6 space-y-6">
            
            <div>
              <h3 className="font-semibold mb-2">Size & Fit</h3>
              <p className="text-muted-foreground">Saree: {product.measurements.length}; Width: {product.measurements.width}</p>
              <p className="text-muted-foreground">Blouse: Unstitched</p>
            </div>
            
            <div>
              <h3 className="font-semibold mb-2">Measurements</h3>
              <p className="text-muted-foreground">Length: {product.measurements.length}, Width: {product.measurements.width}</p>
            </div>
            <div>
              <h3 className="font-semibold mb-2">Occasion</h3>
              <p className="text-muted-foreground">{product.occasion || "All occasions"}</p>
            </div>
            <div>
              <h3 className="font-semibold mb-2">Product Code</h3>
              <p className="text-muted-foreground">{product.id}</p>
              <p className="text-xs text-muted-foreground">Note: Product color may slightly vary due to lighting or monitor settings.</p>
            </div>
          </TabsContent>
          <TabsContent value="care" className="mt-6">
            <p className="text-muted-foreground">{product.care}</p>
          </TabsContent>
          <TabsContent value="reviews" className="mt-6 space-y-6">
            {product.reviews.length > 0 ? (
              product.reviews.map((review) => (
                <div key={review.id} className="border-b pb-6">
                  <div className="flex items-center justify-between mb-2">
                    <div>
                      <p className="font-semibold">{review.author}</p>
                      <div className="flex items-center gap-1">
                        {[...Array(5)].map((_, i) => (
                          <Star
                            key={i}
                            className={`h-4 w-4 ${
                              i < review.rating ? "fill-accent text-accent" : "text-muted"
                            }`}
                          />
                        ))}
                      </div>
                    </div>
                    <span className="text-sm text-muted-foreground">{review.date}</span>
                  </div>
                  <p className="text-muted-foreground">{review.comment}</p>
                </div>
              ))
            ) : (
              <p className="text-muted-foreground">No reviews yet. Be the first to review!</p>
            )}
          </TabsContent>
        </Tabs>

        {/* Related Products */}
        <div>
          <h2 className="font-serif text-3xl font-bold mb-8">You May Also Like</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {relatedProducts.map((product) => (
              <ProductCard key={product.id} product={product} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProductDetail;
