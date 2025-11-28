import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import { fileURLToPath } from "url";
import { MongoClient } from "mongodb";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import crypto from "crypto";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import registerProducts from "./routes/products.js";
import registerCategories from "./routes/categories.js";
import registerSubcategories from "./routes/subcategories.js";
import registerAuth from "./routes/auth.js";
import registerUpload from "./routes/upload.js";
import registerBanners from "./routes/banners.js";
import registerBestsellers from "./routes/bestsellers.js";
import registerCart from "./routes/cart.js";
import registerOrders from "./routes/orders.js";
import registerAdminOrders from "./routes/adminOrders.js";
import registerWishlist from "./routes/wishlist.js";
import registerCategoryTiles from "./routes/categoryTiles.js";
import registerCarousel from "./routes/carousel.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, ".env") });
const app = express();
app.use(cors({
  origin: [
    "https://ecom.speshwayhrms.com",
    "http://localhost:8080",
    "http://localhost:5173"
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const dataPath = path.join(__dirname, "data", "products.json");
let products = [];
let dbClient = null;
let db = null;
let s3 = null;
const categoriesPath = path.join(__dirname, "data", "categories.json");
let categories = [];
const bannersPath = path.join(__dirname, "data", "banners.json");
let banners = [];
const bestsellersPath = path.join(__dirname, "data", "bestsellers.json");
let bestsellerIds = [];
const subcategoriesPath = path.join(__dirname, "data", "subcategories.json");
let subcategories = {};
const cartsPath = path.join(__dirname, "data", "carts.json");
let carts = {};
const ordersPath = path.join(__dirname, "data", "orders.json");
let orders = {};
let lastCheckout = {};
const wishlistsPath = path.join(__dirname, "data", "wishlists.json");
let wishlists = {};
const categoryTilesPath = path.join(__dirname, "data", "category_tiles.json");
let categoryTiles = {};
const usersPath = path.join(__dirname, "data", "users.json");
let fileUsers = [];
const carouselPath = path.join(__dirname, "data", "carousel.json");
let carousel = [];

function loadData() {
  try {
    const raw = fs.readFileSync(dataPath, "utf-8");
    products = JSON.parse(raw);
  } catch (e) {
    products = [];
  }
  try {
    const raw = fs.readFileSync(categoriesPath, "utf-8");
    categories = JSON.parse(raw);
  } catch (e) {
    categories = Array.from(new Set(products.map(p => p.category).filter(Boolean)));
    try { fs.mkdirSync(path.dirname(categoriesPath), { recursive: true }); } catch {}
    try { fs.writeFileSync(categoriesPath, JSON.stringify(categories, null, 2)); } catch {}
  }
  try {
    const raw = fs.readFileSync(bannersPath, "utf-8");
    banners = JSON.parse(raw);
  } catch (e) {
    banners = [];
    try { fs.mkdirSync(path.dirname(bannersPath), { recursive: true }); } catch {}
    try { fs.writeFileSync(bannersPath, JSON.stringify(banners, null, 2)); } catch {}
  }
  try {
    const raw = fs.readFileSync(bestsellersPath, "utf-8");
    bestsellerIds = JSON.parse(raw);
  } catch (e) {
    bestsellerIds = [];
    try { fs.mkdirSync(path.dirname(bestsellersPath), { recursive: true }); } catch {}
    try { fs.writeFileSync(bestsellersPath, JSON.stringify(bestsellerIds, null, 2)); } catch {}
  }
  try {
    const raw = fs.readFileSync(subcategoriesPath, "utf-8");
    subcategories = JSON.parse(raw);
  } catch (e) {
    subcategories = {};
    try { fs.mkdirSync(path.dirname(subcategoriesPath), { recursive: true }); } catch {}
    try { fs.writeFileSync(subcategoriesPath, JSON.stringify(subcategories, null, 2)); } catch {}
  }
  try {
    const raw = fs.readFileSync(cartsPath, "utf-8");
    carts = JSON.parse(raw);
  } catch (e) {
    carts = {};
    try { fs.mkdirSync(path.dirname(cartsPath), { recursive: true }); } catch {}
    try { fs.writeFileSync(cartsPath, JSON.stringify(carts, null, 2)); } catch {}
  }
  try {
    const raw = fs.readFileSync(ordersPath, "utf-8");
    orders = JSON.parse(raw);
  } catch (e) {
    orders = {};
    try { fs.mkdirSync(path.dirname(ordersPath), { recursive: true }); } catch {}
    try { fs.writeFileSync(ordersPath, JSON.stringify(orders, null, 2)); } catch {}
  }
  try {
    const raw = fs.readFileSync(wishlistsPath, "utf-8");
    wishlists = JSON.parse(raw);
  } catch (e) {
    wishlists = {};
    try { fs.mkdirSync(path.dirname(wishlistsPath), { recursive: true }); } catch {}
    try { fs.writeFileSync(wishlistsPath, JSON.stringify(wishlists, null, 2)); } catch {}
  }
  try {
    const raw = fs.readFileSync(categoryTilesPath, "utf-8");
    categoryTiles = JSON.parse(raw);
  } catch (e) {
    categoryTiles = {};
    try { fs.mkdirSync(path.dirname(categoryTilesPath), { recursive: true }); } catch {}
    try { fs.writeFileSync(categoryTilesPath, JSON.stringify(categoryTiles, null, 2)); } catch {}
  }
  try {
    const raw = fs.readFileSync(usersPath, "utf-8");
    fileUsers = JSON.parse(raw);
  } catch (e) {
    fileUsers = [];
    try { fs.mkdirSync(path.dirname(usersPath), { recursive: true }); } catch {}
    try { fs.writeFileSync(usersPath, JSON.stringify(fileUsers, null, 2)); } catch {}
  }
  try {
    const raw = fs.readFileSync(carouselPath, "utf-8");
    carousel = JSON.parse(raw);
  } catch (e) {
    carousel = [];
    try { fs.mkdirSync(path.dirname(carouselPath), { recursive: true }); } catch {}
    try { fs.writeFileSync(carouselPath, JSON.stringify(carousel, null, 2)); } catch {}
  }
}

loadData();

async function initDb() {
  const uri = process.env.MONGO_URI;
  if (!uri) return;
  try {
    dbClient = new MongoClient(uri);
    await dbClient.connect();
    const dbName = process.env.DB_NAME || "ecom";
    db = dbClient.db(dbName);
    const coll = db.collection("products");
    const count = await coll.countDocuments();
    if (count === 0 && products.length > 0) {
      await coll.insertMany(products);
    }

    const users = db.collection("users");
    try { await users.createIndex({ email: 1 }, { unique: true }); } catch {}
    // migrate file-based data to Mongo when collections are empty
    try {
      const catColl = db.collection("categories");
      if (await catColl.countDocuments() === 0 && Array.isArray(categories) && categories.length) {
        await catColl.insertMany(categories.map((name) => ({ name })));
      }
      const subColl = db.collection("subcategories");
      if (await subColl.countDocuments() === 0 && subcategories && typeof subcategories === "object") {
        const rows = Object.entries(subcategories).flatMap(([category, arr]) => (arr || []).map((name) => ({ category, name })));
        if (rows.length) await subColl.insertMany(rows);
      }
      const banColl = db.collection("banners");
      if (await banColl.countDocuments() === 0 && Array.isArray(banners) && banners.length) {
        await banColl.insertMany(banners.map((url) => ({ url })));
      }
      const bestColl = db.collection("bestsellers");
      if (await bestColl.countDocuments() === 0 && Array.isArray(bestsellerIds) && bestsellerIds.length) {
        await bestColl.insertMany(bestsellerIds.map((id) => ({ id })));
      }
      const ordColl = db.collection("orders");
      if (await ordColl.countDocuments() === 0 && orders && typeof orders === "object") {
        const rows = Object.entries(orders).flatMap(([user, list]) => (Array.isArray(list) ? list.map((o) => ({ ...o, user })) : []));
        if (rows.length) await ordColl.insertMany(rows);
      }
      const cartColl = db.collection("cart");
      if (await cartColl.countDocuments() === 0 && carts && typeof carts === "object") {
        const rows = Object.entries(carts).flatMap(([user, list]) => (Array.isArray(list) ? list.map((c) => ({ user, productId: c.productId, quantity: Number(c.quantity || 1) })) : []));
        if (rows.length) await cartColl.insertMany(rows);
      }
      const wishColl = db.collection("wishlist");
      if (await wishColl.countDocuments() === 0 && wishlists && typeof wishlists === "object") {
        const rows = Object.entries(wishlists).flatMap(([user, list]) => (Array.isArray(list) ? list.map((w) => ({ user, productId: w.productId })) : []));
        if (rows.length) await wishColl.insertMany(rows);
      }
    } catch {}
  } catch (e) {
    db = null;
  }
}

// upload setup: S3 if configured, else local disk
const hasS3 = Boolean(process.env.S3_BUCKET && process.env.S3_REGION && process.env.S3_ACCESS_KEY_ID && process.env.S3_SECRET_ACCESS_KEY);
if (hasS3) {
  s3 = new S3Client({
    region: process.env.S3_REGION,
    credentials: { accessKeyId: process.env.S3_ACCESS_KEY_ID, secretAccessKey: process.env.S3_SECRET_ACCESS_KEY },
  });
}
const uploadDir = path.join(__dirname, "uploads");
try { fs.mkdirSync(uploadDir, { recursive: true }); } catch {}
const upload = multer({ storage: hasS3 ? multer.memoryStorage() : multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const base = path.basename(file.originalname, ext).replace(/[^a-z0-9_-]/gi, "_");
    cb(null, `${Date.now()}_${base}${ext}`);
  },
}) });

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

function signToken(user) {
  const secret = process.env.JWT_SECRET || "dev-secret";
  return jwt.sign({ id: user._id?.toString(), email: user.email, role: user.role || "user" }, secret, {
    expiresIn: "7d",
  });
}

function authMiddleware(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    const secret = process.env.JWT_SECRET || "dev-secret";
    const payload = jwt.verify(token, secret);
    req.user = payload;
    next();
  } catch (e) {
    res.status(401).json({ error: "Unauthorized" });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  next();
}










const port = process.env.PORT ? Number(process.env.PORT) : 3001;
process.on("uncaughtException", (err) => { try { console.error("uncaughtException", err); } catch {} });
process.on("unhandledRejection", (err) => { try { console.error("unhandledRejection", err); } catch {} });
initDb().finally(() => {
  try {
    registerProducts({
      app,
      getDb: () => db,
      authMiddleware,
      adminOnly,
      getProducts: () => products,
      setProducts: (arr) => { products = arr; },
      saveProducts: saveProductsToFile,
      getCategories: () => categories,
      setCategories: (arr) => { categories = arr; },
      saveCategories: saveCategoriesToFile,
      getSubcategories: () => subcategories,
      saveSubcategories: saveSubcategoriesToFile,
      getOrders: () => orders,
    });
    registerCategories({
      app,
      getDb: () => db,
      authMiddleware,
      adminOnly,
      getCategories: () => categories,
      setCategories: (arr) => { categories = arr; },
      getSubcategories: () => subcategories,
      saveCategories: saveCategoriesToFile,
      saveSubcategories: saveSubcategoriesToFile,
    });
    registerSubcategories({
      app,
      getDb: () => db,
      authMiddleware,
      adminOnly,
      getSubcategories: () => subcategories,
      saveSubcategories: saveSubcategoriesToFile,
    });
    registerAuth({
      app,
      getDb: () => db,
      signToken,
      getFileUsers: () => fileUsers,
      setFileUsers: (arr) => { fileUsers = arr; },
      saveUsers: saveUsersToFile,
      adminInviteCode: process.env.ADMIN_INVITE_CODE || "",
      authMiddleware,
    });
    registerUpload({
      app,
      getDb: () => db,
      authMiddleware,
      adminOnly,
      upload,
      s3,
      hasS3,
      uploadDir,
    });
    registerBanners({
      app,
      getDb: () => db,
      authMiddleware,
      adminOnly,
      getBanners: () => banners,
      setBanners: (arr) => { banners = arr; },
      saveBanners: saveBannersToFile,
    });
    registerCarousel({
      app,
      getDb: () => db,
      authMiddleware,
      adminOnly,
      getCarousel: () => carousel,
      setCarousel: (arr) => { carousel = arr; },
      saveCarousel: saveCarouselToFile,
    });
    registerBestsellers({
      app,
      getDb: () => db,
      authMiddleware,
      adminOnly,
      getBestsellers: () => bestsellerIds,
      setBestsellers: (arr) => { bestsellerIds = arr; },
      saveBestsellers: saveBestsellersToFile,
      getProducts: () => products,
    });
    registerCart({
      app,
      getDb: () => db,
      authMiddleware,
      getProducts: () => products,
      getCarts: () => carts,
      setCarts: (obj) => { carts = obj; },
      saveCarts: saveCartsToFile,
    });
    registerOrders({
      app,
      getDb: () => db,
      authMiddleware,
      adminOnly,
      getOrders: () => orders,
      setOrders: (obj) => { orders = obj; },
      saveOrders: saveOrdersToFile,
      getLastCheckout,
      setLastCheckout,
      getProducts: () => products,
      getCarts: () => carts,
      setCarts: (obj) => { carts = obj; },
      saveCarts: saveCartsToFile,
    });
    registerAdminOrders({
      app,
      getDb: () => db,
      authMiddleware,
      adminOnly,
      getOrders: () => orders,
      setOrders: (obj) => { orders = obj; },
      saveOrders: saveOrdersToFile,
    });
    registerWishlist({
      app,
      getDb: () => db,
      authMiddleware,
      getWishlists: () => wishlists,
      setWishlists: (obj) => { wishlists = obj; },
      saveWishlists: saveWishlistsToFile,
    });
    registerCategoryTiles({
      app,
      getDb: () => db,
      authMiddleware,
      adminOnly,
      getCategoryTiles: () => categoryTiles,
      setCategoryTiles: (obj) => { categoryTiles = obj; },
      saveCategoryTiles: saveCategoryTilesToFile,
      resolveLocal,
      uploadLocalPath,
    });
    app.listen(port, () => {
      console.log(`[backend] listening on http://localhost:${port}`);
    });
  } catch (e) {
    console.error("listen-error", e);
  }
});

function saveProductsToFile() {
  try {
    fs.writeFileSync(dataPath, JSON.stringify(products, null, 2));
  } catch {}
}

function saveCategoriesToFile() {
  try {
    fs.writeFileSync(categoriesPath, JSON.stringify(categories, null, 2));
  } catch {}
}
function saveBannersToFile() {
  try {
    fs.writeFileSync(bannersPath, JSON.stringify(banners, null, 2));
  } catch {}
}
function saveBestsellersToFile() {
  try {
    fs.writeFileSync(bestsellersPath, JSON.stringify(bestsellerIds, null, 2));
  } catch {}
}
function saveSubcategoriesToFile() {
  try {
    fs.writeFileSync(subcategoriesPath, JSON.stringify(subcategories, null, 2));
  } catch {}
}
function saveCartsToFile() {
  try {
    fs.writeFileSync(cartsPath, JSON.stringify(carts, null, 2));
  } catch {}
}
function saveOrdersToFile() {
  try {
    fs.writeFileSync(ordersPath, JSON.stringify(orders, null, 2));
  } catch {}
}
function saveWishlistsToFile() {
  try {
    fs.writeFileSync(wishlistsPath, JSON.stringify(wishlists, null, 2));
  } catch {}
}
function getLastCheckout() { return lastCheckout; }
function setLastCheckout(obj) { lastCheckout = obj; }

function isHttp(u) {
  return typeof u === "string" && /^https?:\/\//.test(u);
}
function extMime(ext) {
  const e = (ext || "").toLowerCase();
  if (e === ".jpg" || e === ".jpeg") return "image/jpeg";
  if (e === ".png") return "image/png";
  if (e === ".webp") return "image/webp";
  if (e === ".gif") return "image/gif";
  return "application/octet-stream";
}
function resolveLocal(p) {
  if (!p || typeof p !== "string") return null;
  if (p.startsWith("/uploads/")) {
    return path.join(uploadDir, path.basename(p));
  }
  if (p.startsWith("/images/")) {
    return path.join(process.cwd(), "..", "frontend", "public", "images", path.basename(p));
  }
  return null;
}
async function uploadLocalPath(localPath, baseName) {
  try {
    const buf = fs.readFileSync(localPath);
    const ext = path.extname(baseName || localPath);
    const key = `uploads/${Date.now()}_${path.basename(baseName || localPath)}`;
    await s3.send(new PutObjectCommand({ Bucket: process.env.S3_BUCKET, Key: key, Body: buf, ContentType: extMime(ext) }));
    return `https://${process.env.S3_BUCKET}.s3.${process.env.S3_REGION}.amazonaws.com/${key}`;
  } catch {
    return null;
  }
}
async function migrateImagesArray(arr) {
  if (!Array.isArray(arr)) return arr;
  const out = [];
  for (const u of arr) {
    if (isHttp(u) || !hasS3) { out.push(u); continue; }
    const lp = resolveLocal(u);
    if (!lp) { out.push(u); continue; }
    const url = await uploadLocalPath(lp, path.basename(u));
    out.push(url || u);
  }
  return out;
}
async function migrateProduct(p) {
  const images = await migrateImagesArray(p.images || []);
  const reviews = Array.isArray(p.reviews) ? await Promise.all(p.reviews.map(async (r) => ({ ...r, images: await migrateImagesArray(r.images || []) }))) : (p.reviews || []);
  return { ...p, images, reviews };
}
function saveCategoryTilesToFile() {
  try {
    fs.writeFileSync(categoryTilesPath, JSON.stringify(categoryTiles, null, 2));
  } catch {}
}
function saveUsersToFile() {
  try {
    fs.writeFileSync(usersPath, JSON.stringify(fileUsers, null, 2));
  } catch {}
}
function saveCarouselToFile() {
  try {
    fs.writeFileSync(carouselPath, JSON.stringify(carousel, null, 2));
  } catch {}
}