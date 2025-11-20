export interface Product {
  id: string;
  name: string;
  brand: string;
  images: string[];
  price: number;
  originalPrice?: number;
  discount?: number;
  colors: string[];
  fabrics: string[];
  measurements: {
    length: string;
    width: string;
  };
  care: string;
  details?: string;
  saveAmount?: number;
  colorLinks?: { image: string; url: string }[];
  descriptionSections?: {
    productSpecifications?: string;
    shippingInformation?: string;
    moreInformation?: string;
    needHelp?: string;
    faqs?: string;
    returnPolicy?: string;
  };
  stock: number;
  rating: number;
  reviews: Review[];
  category: string;
  occasion?: string;
}

export interface Review {
  id: string;
  author: string;
  rating: number;
  comment: string;
  date: string;
}

export interface CartItem {
  product: Product;
  quantity: number;
  selectedColor?: string;
}
