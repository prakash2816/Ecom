import { useState, useEffect } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { apiBase } from "@/lib/auth";
import hero1 from "@/assets/hero-saree-1.jpg";
import hero2 from "@/assets/hero-saree-2.jpg";
import hero3 from "@/assets/hero-saree-3.jpg";

const defaultSlides = [
  { image: hero1, title: "Timeless Elegance", subtitle: "Discover our exquisite collection of handcrafted silk sarees" },
  { image: hero2, title: "Premium Craftsmanship", subtitle: "Intricate designs with traditional artistry" },
  { image: hero3, title: "Luxury Redefined", subtitle: "Experience the finest sarees for every occasion" },
];

const HeroCarousel = () => {
  const [current, setCurrent] = useState(0);
  const [slides, setSlides] = useState(defaultSlides);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrent((prev) => (prev + 1) % slides.length);
    }, 5000);
    return () => clearInterval(timer);
  }, [slides.length]);

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${apiBase}/api/carousel`);
        let images: string[] = [];
        if (res.ok) images = await res.json();
        if (!Array.isArray(images) || images.length === 0) {
          const b = await fetch(`${apiBase}/api/banners`);
          if (b.ok) images = await b.json();
        }
        if (Array.isArray(images) && images.length) {
          const next = images.slice(0, 5).map((img, i) => ({ image: img, title: defaultSlides[i % defaultSlides.length].title, subtitle: defaultSlides[i % defaultSlides.length].subtitle }));
          setSlides(next);
        }
      } catch (e) { void e; }
    })();
  }, []);

  const next = () => setCurrent((prev) => (prev + 1) % slides.length);
  const prev = () => setCurrent((prev) => (prev - 1 + slides.length) % slides.length);

  return (
    <div className="relative h-[600px] overflow-hidden">
      {slides.map((slide, index) => (
        <div
          key={index}
          className={`absolute inset-0 transition-opacity duration-700 ${
            index === current ? "opacity-100" : "opacity-0"
          }`}
        >
          <img
            src={slide.image}
            alt={slide.title}
            className="w-full h-full object-cover"
          />
          <div className="absolute inset-0 bg-gradient-to-r from-black/60 to-transparent" />
          <div className="absolute inset-0 flex items-center">
            <div className="container px-4">
              <div className="max-w-2xl space-y-4 text-white">
                <h1 className="font-serif text-5xl md:text-6xl font-bold leading-tight">
                  {slide.title}
                </h1>
                <p className="text-xl md:text-2xl text-white/90">
                  {slide.subtitle}
                </p>
                <Button size="lg" className="mt-4 bg-primary hover:bg-primary/90">
                  Shop Now
                </Button>
              </div>
            </div>
          </div>
        </div>
      ))}

      <Button
        variant="ghost"
        size="icon"
        className="absolute left-4 top-1/2 -translate-y-1/2 h-12 w-12 rounded-full bg-white/20 hover:bg-white/30 text-white"
        onClick={prev}
      >
        <ChevronLeft className="h-6 w-6" />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        className="absolute right-4 top-1/2 -translate-y-1/2 h-12 w-12 rounded-full bg-white/20 hover:bg-white/30 text-white"
        onClick={next}
      >
        <ChevronRight className="h-6 w-6" />
      </Button>

      <div className="absolute bottom-6 left-1/2 -translate-x-1/2 flex gap-2">
        {slides.map((_, index) => (
          <button
            key={index}
            className={`h-2 rounded-full transition-all ${
              index === current ? "w-8 bg-white" : "w-2 bg-white/50"
            }`}
            onClick={() => setCurrent(index)}
          />
        ))}
      </div>
    </div>
  );
};

export default HeroCarousel;
