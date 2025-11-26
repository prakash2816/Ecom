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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, ".env") });
const app = express();
app.use(cors());
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
    subcategories = {
      Lenin: [
        "Lenin Kanchi Border",
        "Lenin Bathik Prints",
        "Lenin Printed",
        "Lenin Ikkat",
        "Lenin Tissue",
        "Lenin Shibori Sarees",
        "Lenin Digital Print",
        "Lenin Kalamkari",
        "Lenin Silk Sateen Border",
        "Kantha Work",
        "Summer Special Lenin Sarees",
        "Lenin Sequence Work",
        "Lenin Sarees",
      ],
    };
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

app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, name, invite } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });
    const role = invite && process.env.ADMIN_INVITE_CODE && invite === process.env.ADMIN_INVITE_CODE ? "admin" : "user";
    if (!db) {
      const existsFile = fileUsers.find((u) => u.email === email);
      if (existsFile) return res.status(409).json({ error: "Email already registered" });
      const hash = bcrypt.hashSync(password, 10);
      fileUsers.push({ email, name: name || "", password: hash, role });
      saveUsersToFile();
      const token = signToken({ email, role });
      return res.json({ token, role });
    }
    const existing = await db.collection("users").findOne({ email });
    if (existing) return res.status(409).json({ error: "Email already registered" });
    const hash = bcrypt.hashSync(password, 10);
    const user = { email, name: name || "", password: hash, role };
    let insertedId;
    try {
      const r = await db.collection("users").insertOne(user);
      insertedId = r.insertedId;
    } catch (err) {
      if (err && err.code === 11000) return res.status(409).json({ error: "Email already registered" });
      try {
        const existsFile = fileUsers.find((u) => u.email === email);
        if (existsFile) return res.status(409).json({ error: "Email already registered" });
        fileUsers.push({ email, name: name || "", password: hash, role });
        saveUsersToFile();
        const token = signToken({ email, role });
        return res.json({ token, role });
      } catch (e2) {
        return res.status(500).json({ error: "Registration failed" });
      }
    }
    const token = signToken({ _id: insertedId, email, role });
    res.json({ token, role });
  } catch (e) {
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  if (!db) {
    const fuser = fileUsers.find((u) => u.email === email);
    if (fuser && bcrypt.compareSync(password, fuser.password)) {
      const token = signToken({ email: fuser.email, role: fuser.role || "user" });
      return res.json({ token, role: fuser.role || "user" });
    }
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const user = await db.collection("users").findOne({ email });
  if (!user) {
    const fuser = fileUsers.find((u) => u.email === email);
    if (!fuser) return res.status(401).json({ error: "Invalid credentials" });
    const okFile = bcrypt.compareSync(password, fuser.password);
    if (!okFile) return res.status(401).json({ error: "Invalid credentials" });
    const token = signToken({ email: fuser.email, role: fuser.role || "user" });
    return res.json({ token, role: fuser.role || "user" });
  }
  const ok = bcrypt.compareSync(password, user.password);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });
  const token = signToken(user);
  res.json({ token, role: user.role || "user" });
  } catch (e) {
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    if (!db) {
      return res.json({ email: req.user.email, role: req.user.role || "user", name: req.user.email.split("@")[0] });
    }
    const user = await db.collection("users").findOne({ email: req.user.email }, { projection: { password: 0 } });
    res.json(user);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

app.get("/api/products", async (req, res, next) => {
  try { return next();
    if (db) {
      const items = await db.collection("products").find({}).sort({ createdAt: -1, _id: -1 }).toArray();
      const sanitized = items.map((p) => ({
        ...p,
        images: Array.isArray(p.images)
          ? p.images.filter((u) => typeof u === "string" && u && !u.startsWith("blob:"))
          : [],
      }));
      res.json(sanitized);
      return;
    }
    const sorted = [...products]
      .map((p) => ({
        ...p,
        images: Array.isArray(p.images)
          ? p.images.filter((u) => typeof u === "string" && u && !u.startsWith("blob:"))
          : [],
      }))
      .sort((a, b) => (Number(b.createdAt || 0) - Number(a.createdAt || 0)));
    res.json(sorted);
  } catch (e) {
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/api/products/:id", async (req, res, next) => {
  try { return next();
    if (db) {
      const item = await db.collection("products").findOne({ id: req.params.id });
      if (!item) {
        res.status(404).json({ error: "Not found" });
        return;
      }
      const sanitized = {
        ...item,
        images: Array.isArray(item.images)
          ? item.images.filter((u) => typeof u === "string" && u && !u.startsWith("blob:"))
          : [],
      };
      res.json(sanitized);
      return;
    }
    const item = products.find(p => p.id === req.params.id);
    if (!item) {
      res.status(404).json({ error: "Not found" });
      return;
    }
    const sanitized = {
      ...item,
      images: Array.isArray(item.images)
        ? item.images.filter((u) => typeof u === "string" && u && !u.startsWith("blob:"))
        : [],
    };
    res.json(sanitized);
  } catch (e) {
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/products", authMiddleware, adminOnly, async (req, res, next) => {
  try { return next();
    const payload = req.body || {};
    if (!payload.name || !payload.price) return res.status(400).json({ error: "Missing fields" });
  const doc = {
      id: payload.id || crypto.randomUUID(),
      name: payload.name,
      brand: payload.brand || "",
      images: payload.images || [],
      price: Number(payload.price),
      originalPrice: payload.originalPrice ? Number(payload.originalPrice) : undefined,
      saveAmount: payload.saveAmount ? Number(payload.saveAmount) : undefined,
      discount: payload.discount ? Number(payload.discount) : undefined,
      colors: payload.colors || [],
      fabrics: payload.fabrics || [],
      measurements: payload.measurements || { length: "", width: "" },
      care: payload.care || "",
      colorLinks: Array.isArray(payload.colorLinks) ? payload.colorLinks : [],
      stock: payload.stock ? Number(payload.stock) : 0,
      rating: payload.rating ? Number(payload.rating) : 0,
      reviews: [],
      category: payload.category || "",
      occasion: payload.occasion || "",
      createdAt: Date.now(),
    };
    if (!db) {
      products.push(doc);
      if (doc.category) {
        const parent = Object.keys(subcategories).find((cat) => (subcategories[cat] || []).includes(doc.category)) || doc.category;
        if (!categories.includes(parent)) {
          categories.push(parent);
          saveCategoriesToFile();
        }
      }
      saveProductsToFile();
      return res.json({ success: true, id: doc.id });
    }
    await db.collection("products").insertOne(doc);
    res.json({ success: true, id: doc.id });
  } catch (e) {
    res.status(500).json({ error: "Create failed" });
  }
});

app.put("/api/products/:id", authMiddleware, adminOnly, async (req, res, next) => {
  try { return next();
    if (!db) {
      const id = req.params.id;
      const idx = products.findIndex(p => p.id === id);
      if (idx === -1) return res.status(404).json({ error: "Not found" });
      products[idx] = { ...products[idx], ...req.body };
      saveProductsToFile();
      return res.json({ success: true });
    }
    const id = req.params.id;
    const update = { $set: { ...req.body } };
    const r = await db.collection("products").updateOne({ id }, update);
    if (!r.matchedCount) return res.status(404).json({ error: "Not found" });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Update failed" });
  }
});

app.delete("/api/products/:id", authMiddleware, adminOnly, async (req, res, next) => {
  try { return next();
    if (!db) {
      const id = req.params.id;
      const before = products.length;
      products = products.filter(p => p.id !== id);
      saveProductsToFile();
      if (products.length === before) return res.status(404).json({ error: "Not found" });
      return res.json({ success: true });
    }
    const id = req.params.id;
    const r = await db.collection("products").deleteOne({ id });
    if (!r.deletedCount) return res.status(404).json({ error: "Not found" });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Delete failed" });
  }
});

app.post("/api/checkout", authMiddleware, (req, res) => {
  try {
    const email = req.user?.email;
    lastCheckout[email] = { ...(req.body || {}), date: Date.now() };
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

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
    app.listen(port, () => {
      console.log(`[backend] listening on http://localhost:${port}`);
    });
  } catch (e) {
    console.error("listen-error", e);
  }
});

app.post("/api/upload", authMiddleware, adminOnly, upload.array("files", 10), async (req, res) => {
  try {
    if (s3) {
      const uploaded = [];
      for (const file of (req.files || [])) {
        const ext = path.extname(file.originalname);
        const base = path.basename(file.originalname, ext).replace(/[^a-z0-9_-]/gi, "_");
        const Key = `uploads/${Date.now()}_${base}${ext}`;
        try {
          await s3.send(new PutObjectCommand({ Bucket: process.env.S3_BUCKET, Key, Body: file.buffer, ContentType: file.mimetype }));
          const url = `https://${process.env.S3_BUCKET}.s3.${process.env.S3_REGION}.amazonaws.com/${Key}`;
          uploaded.push(url);
        } catch (err) {
          const localName = `${Date.now()}_${base}${ext}`;
          const localPath = path.join(uploadDir, localName);
          try { fs.writeFileSync(localPath, file.buffer); uploaded.push(`/uploads/${localName}`); } catch {}
        }
      }
      return res.json({ urls: uploaded });
    }
    const files = (req.files || []).map((f) => `/uploads/${path.basename(f.path)}`);
    res.json({ urls: files });
  } catch (e) {
    res.status(500).json({ error: "Upload failed", detail: String(e?.message || e) });
  }
});
app.post("/api/upload-public", authMiddleware, upload.array("files", 3), async (req, res) => {
  try {
    if (s3) {
      const uploaded = [];
      for (const file of (req.files || [])) {
        const ext = path.extname(file.originalname);
        const base = path.basename(file.originalname, ext).replace(/[^a-z0-9_-]/gi, "_");
        const Key = `uploads/${Date.now()}_${base}${ext}`;
        try {
          await s3.send(new PutObjectCommand({ Bucket: process.env.S3_BUCKET, Key, Body: file.buffer, ContentType: file.mimetype }));
          const url = `https://${process.env.S3_BUCKET}.s3.${process.env.S3_REGION}.amazonaws.com/${Key}`;
          uploaded.push(url);
        } catch (err) {
          const localName = `${Date.now()}_${base}${ext}`;
          const localPath = path.join(uploadDir, localName);
          try { fs.writeFileSync(localPath, file.buffer); uploaded.push(`/uploads/${localName}`); } catch {}
        }
      }
      return res.json({ urls: uploaded });
    }
    const files = (req.files || []).map((f) => `/uploads/${path.basename(f.path)}`);
    res.json({ urls: files });
  } catch (e) {
    res.status(500).json({ error: "Upload failed", detail: String(e?.message || e) });
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
app.post("/api/admin/migrate-images", authMiddleware, adminOnly, async (req, res) => {
  try {
    if (!hasS3 || !s3) return res.status(400).json({ error: "S3 not configured" });
    let migrated = 0;
    if (db) {
      const all = await db.collection("products").find({}).toArray();
      for (const p of all) {
        const np = await migrateProduct(p);
        if (JSON.stringify(np.images) !== JSON.stringify(p.images) || JSON.stringify(np.reviews) !== JSON.stringify(p.reviews)) migrated++;
        await db.collection("products").updateOne({ _id: p._id }, { $set: { images: np.images, reviews: np.reviews } });
      }
      try {
        const bannersColl = db.collection("banners");
        const bannersDocs = await bannersColl.find({}).toArray();
        for (const b of bannersDocs) {
          const newUrl = await migratePathToS3(b.url);
          if (newUrl !== b.url) { migrated++; await bannersColl.updateOne({ _id: b._id }, { $set: { url: newUrl } }); }
        }
      } catch {}
    } else {
      const next = [];
      for (const p of products) {
        const np = await migrateProduct(p);
        next.push(np);
      }
      products = next;
      saveProductsToFile();
      migrated = products.length;
      try {
        const updated = [];
        for (const u of banners) { updated.push(await migratePathToS3(u)); }
        banners = updated; saveBannersToFile();
      } catch {}
      try {
        const ct = {};
        for (const [k, v] of Object.entries(categoryTiles || {})) { ct[k] = typeof v === "string" ? await migratePathToS3(v) : v; }
        categoryTiles = ct;
        saveCategoryTilesToFile();
      } catch {}
    }
    res.json({ success: true, migrated });
  } catch (e) {
    res.status(500).json({ error: "Migration failed" });
  }
});

app.get("/api/admin/s3-check", authMiddleware, adminOnly, async (req, res) => {
  try {
    const info = { configured: Boolean(hasS3 && s3), bucket: process.env.S3_BUCKET, region: process.env.S3_REGION };
    if (!hasS3 || !s3) return res.status(400).json(info);
    try {
      const testKey = `uploads/ping_${Date.now()}.txt`;
      await s3.send(new PutObjectCommand({ Bucket: process.env.S3_BUCKET, Key: testKey, Body: Buffer.from("ping") }));
      info.putTest = { ok: true, key: testKey, url: `https://${process.env.S3_BUCKET}.s3.${process.env.S3_REGION}.amazonaws.com/${testKey}` };
    } catch (e) {
      info.putTest = { ok: false, error: String(e?.message || e) };
    }
    res.json(info);
  } catch (e) {
    res.status(500).json({ error: "Check failed" });
  }
});
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
// Categories API
app.get("/api/categories", async (req, res, next) => {
  try { return next();
    if (db) {
      const cats = await db.collection("categories").find({}).toArray();
      const catNames = cats.map(c => c.name);
      const subcats = await db.collection("subcategories").find({}).toArray();
      const dbSubNames = new Set(subcats.map(s => s.name));
      const fileSubNames = new Set(Object.values(subcategories).flat());
      const allSubNames = new Set([...dbSubNames, ...fileSubNames]);
      const filtered = catNames.filter(name => !allSubNames.has(name));
      return res.json(filtered);
    }
    const allSubNames = new Set(Object.values(subcategories).flat());
    const filtered = categories.filter(name => !allSubNames.has(name));
    return res.json(filtered);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

app.post("/api/categories", authMiddleware, adminOnly, async (req, res, next) => {
  try { return next();
    const { name } = req.body || {};
    if (!name) return res.status(400).json({ error: "Name required" });
    if (db) {
      const exists = await db.collection("categories").findOne({ name });
      if (exists) return res.json({ success: true });
      await db.collection("categories").insertOne({ name });
      return res.json({ success: true });
    }
    if (!categories.includes(name)) {
      categories.push(name);
      saveCategoriesToFile();
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

app.put("/api/categories", authMiddleware, adminOnly, async (req, res, next) => {
  try { return next();
    const { oldName, newName } = req.body || {};
    if (!oldName || !newName) return res.status(400).json({ error: "oldName and newName required" });
    if (db) {
      const exists = await db.collection("categories").findOne({ name: oldName });
      if (!exists) return res.status(404).json({ error: "Not found" });
      await db.collection("categories").updateOne({ name: oldName }, { $set: { name: newName } });
      // also update subcategories parent references
      await db.collection("subcategories").updateMany({ category: oldName }, { $set: { category: newName } });
      return res.json({ success: true });
    }
    const idx = categories.findIndex((c) => c === oldName);
    if (idx === -1) return res.status(404).json({ error: "Not found" });
    categories[idx] = newName;
    if (subcategories[oldName]) {
      subcategories[newName] = subcategories[oldName];
      delete subcategories[oldName];
    }
    saveCategoriesToFile();
    saveSubcategoriesToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

app.get("/api/banners", async (req, res) => {
  try {
    if (db) {
      const list = await db.collection("banners").find({}).toArray();
      return res.json(list.map(b => b.url));
    }
    return res.json(banners);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

app.post("/api/banners", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { urls } = req.body || {};
    const arr = Array.isArray(urls) ? urls : [];
    if (!arr.length) return res.status(400).json({ error: "urls required" });
    if (db) {
      for (const u of arr) {
        const exists = await db.collection("banners").findOne({ url: u });
        if (!exists) await db.collection("banners").insertOne({ url: u });
      }
      return res.json({ success: true });
    }
    for (const u of arr) {
      if (!banners.includes(u)) banners.push(u);
    }
    saveBannersToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

app.delete("/api/banners", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { url } = req.body || {};
    if (!url) return res.status(400).json({ error: "url required" });
    if (db) {
      await db.collection("banners").deleteOne({ url });
      return res.json({ success: true });
    }
    banners = banners.filter(b => b !== url);
    saveBannersToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

app.get("/api/bestsellers", async (req, res) => {
  try {
    if (db) {
      const list = await db.collection("products").find({ id: { $in: bestsellerIds } }).toArray();
      return res.json(list);
    }
    const list = products.filter(p => bestsellerIds.includes(p.id));
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

app.post("/api/bestsellers", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { ids } = req.body || {};
    const arr = Array.isArray(ids) ? ids : [];
    if (!arr.length) return res.status(400).json({ error: "ids required" });
    if (db) {
      for (const id of arr) {
        const exists = await db.collection("bestsellers").findOne({ id });
        if (!exists) await db.collection("bestsellers").insertOne({ id });
      }
      const list = await db.collection("products").find({ id: { $in: arr } }).toArray();
      return res.json({ success: true, added: list.map(p => p.id) });
    }
    for (const id of arr) {
      if (!bestsellerIds.includes(id)) bestsellerIds.push(id);
    }
    saveBestsellersToFile();
    res.json({ success: true, added: arr });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

app.delete("/api/bestsellers/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const id = req.params.id;
    if (db) {
      await db.collection("bestsellers").deleteOne({ id });
      return res.json({ success: true });
    }
    bestsellerIds = bestsellerIds.filter(x => x !== id);
    saveBestsellersToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

// Subcategories API
app.get("/api/subcategories", async (req, res, next) => {
  try { return next();
    const category = (req.query.category || "").toString();
    if (!category) return res.status(400).json({ error: "category required" });
    if (db) {
      const list = await db.collection("subcategories").find({ category }).toArray();
      return res.json(list.map((s) => s.name));
    }
    const list = subcategories[category] || [];
    return res.json(list);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

app.post("/api/subcategories", authMiddleware, adminOnly, async (req, res, next) => {
  try { return next();
    const { category, name } = req.body || {};
    if (!category || !name) return res.status(400).json({ error: "category and name required" });
    if (db) {
      const exists = await db.collection("subcategories").findOne({ category, name });
      if (exists) return res.json({ success: true });
      await db.collection("subcategories").insertOne({ category, name });
      return res.json({ success: true });
    }
    const list = subcategories[category] || [];
    if (!list.includes(name)) {
      subcategories[category] = [...list, name];
      saveSubcategoriesToFile();
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

app.put("/api/subcategories", authMiddleware, adminOnly, async (req, res, next) => {
  try { return next();
    const { category, oldName, newName } = req.body || {};
    if (!category || !oldName || !newName) return res.status(400).json({ error: "category, oldName, newName required" });
    if (db) {
      const r = await db.collection("subcategories").updateOne({ category, name: oldName }, { $set: { name: newName } });
      if (!r.matchedCount) return res.status(404).json({ error: "Not found" });
      return res.json({ success: true });
    }
    const list = subcategories[category] || [];
    const idx = list.findIndex((n) => n === oldName);
    if (idx === -1) return res.status(404).json({ error: "Not found" });
    list[idx] = newName;
    subcategories[category] = list;
    saveSubcategoriesToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.delete("/api/categories", authMiddleware, adminOnly, async (req, res, next) => {
  try { return next();
    const body = req.body || {};
    const queryName = (req.query?.name || "").toString();
    const name = body.name || queryName;
    if (!name) return res.status(400).json({ error: "Name required" });
    if (db) {
      await db.collection("categories").deleteOne({ name });
      await db.collection("subcategories").deleteMany({ category: name });
      return res.json({ success: true });
    }
    categories = categories.filter((c) => c !== name);
    if (subcategories[name]) delete subcategories[name];
    saveCategoriesToFile();
    saveSubcategoriesToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.delete("/api/subcategories", authMiddleware, adminOnly, async (req, res, next) => {
  try { return next();
    const body = req.body || {};
    const qCategory = (req.query?.category || "").toString();
    const qName = (req.query?.name || "").toString();
    const category = body.category || qCategory;
    const name = body.name || qName;
    if (!category || !name) return res.status(400).json({ error: "category, name required" });
    if (db) {
      await db.collection("subcategories").deleteOne({ category, name });
      return res.json({ success: true });
    }
    const list = subcategories[category] || [];
    subcategories[category] = list.filter((n) => n !== name);
    saveSubcategoriesToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.get("/api/cart", authMiddleware, async (req, res) => {
  try {
    if (db) {
      const items = await db.collection("cart").find({ user: req.user.email }).toArray();
      const ids = items.map((i) => i.productId);
      const productsList = await db.collection("products").find({ id: { $in: ids } }).toArray();
      const map = new Map(productsList.map((p) => [p.id, p]));
      const result = items.map((i) => ({ product: map.get(i.productId), quantity: i.quantity })).filter((x) => x.product);
      return res.json(result);
    }
    const list = Array.isArray(carts[req.user.email]) ? carts[req.user.email] : [];
    const map = new Map(products.map((p) => [p.id, p]));
    const result = list.map((i) => ({ product: map.get(i.productId), quantity: i.quantity })).filter((x) => x.product);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.post("/api/cart", authMiddleware, async (req, res) => {
  try {
    const { productId, quantity } = req.body || {};
    if (!productId) return res.status(400).json({ error: "productId required" });
    const q = Math.max(1, Number(quantity || 1));
    if (db) {
      const product = await db.collection("products").findOne({ id: productId });
      if (!product) return res.status(404).json({ error: "Product not found" });
      const newQty = Math.min(q, Number(product.stock || 0) || q);
      await db.collection("cart").updateOne({ user: req.user.email, productId }, { $set: { user: req.user.email, productId, quantity: newQty } }, { upsert: true });
      return res.json({ success: true });
    }
    const product = products.find((p) => p.id === productId);
    if (!product) return res.status(404).json({ error: "Product not found" });
    const list = Array.isArray(carts[req.user.email]) ? carts[req.user.email] : [];
    const idx = list.findIndex((i) => i.productId === productId);
    const newQty = Math.min(q, Number(product.stock || 0) || q);
    if (idx >= 0) list[idx].quantity = newQty; else list.push({ productId, quantity: newQty });
    carts[req.user.email] = list;
    saveCartsToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.put("/api/cart", authMiddleware, async (req, res) => {
  try {
    const { productId, quantity } = req.body || {};
    if (!productId || typeof quantity !== "number") return res.status(400).json({ error: "productId, quantity required" });
    const q = Math.max(1, Number(quantity));
    if (db) {
      const product = await db.collection("products").findOne({ id: productId });
      if (!product) return res.status(404).json({ error: "Product not found" });
      const newQty = Math.min(q, Number(product.stock || 0) || q);
      const r = await db.collection("cart").updateOne({ user: req.user.email, productId }, { $set: { quantity: newQty } });
      if (!r.matchedCount) return res.status(404).json({ error: "Not found" });
      return res.json({ success: true });
    }
    const list = Array.isArray(carts[req.user.email]) ? carts[req.user.email] : [];
    const product = products.find((p) => p.id === productId);
    if (!product) return res.status(404).json({ error: "Product not found" });
    const idx = list.findIndex((i) => i.productId === productId);
    if (idx === -1) return res.status(404).json({ error: "Not found" });
    list[idx].quantity = Math.min(q, Number(product.stock || 0) || q);
    carts[req.user.email] = list;
    saveCartsToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.delete("/api/cart", authMiddleware, async (req, res) => {
  try {
    const productId = (req.query.productId || "").toString();
    const all = (req.query.all || "").toString();
    if (db) {
      if (all) {
        await db.collection("cart").deleteMany({ user: req.user.email });
        return res.json({ success: true });
      }
      if (!productId) return res.status(400).json({ error: "productId required" });
      await db.collection("cart").deleteOne({ user: req.user.email, productId });
      return res.json({ success: true });
    }
    if (all) {
      carts[req.user.email] = [];
      saveCartsToFile();
      return res.json({ success: true });
    }
    if (!productId) return res.status(400).json({ error: "productId required" });
    const list = Array.isArray(carts[req.user.email]) ? carts[req.user.email] : [];
    carts[req.user.email] = list.filter((i) => i.productId !== productId);
    saveCartsToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.get("/api/orders", authMiddleware, async (req, res) => {
  try {
    if (db) {
      const list = await db.collection("orders").find({ user: req.user.email }).sort({ createdAt: -1 }).toArray();
      return res.json(list.map((o) => ({ id: o.id || String(o._id), items: o.items || [], status: o.status || "placed", createdAt: o.createdAt || Date.now() })));
    }
    const list = Array.isArray(orders[req.user.email]) ? orders[req.user.email] : [];
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.get("/api/orders/:id", authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    if (db) {
      const o = await db.collection("orders").findOne({ $or: [{ id, user: req.user.email }, { _id: id, user: req.user.email }] });
      if (!o) return res.status(404).json({ error: "Not found" });
      return res.json({ id: o.id || String(o._id), user: o.user, items: o.items || [], status: o.status || "placed", createdAt: o.createdAt || Date.now() });
    }
    const list = Array.isArray(orders[req.user.email]) ? orders[req.user.email] : [];
    const o = list.find((x) => x.id === id);
    if (!o) return res.status(404).json({ error: "Not found" });
    res.json(o);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.post("/api/orders", authMiddleware, async (req, res) => {
  try {
    const body = req.body || {};
    let items = Array.isArray(body.items) ? body.items : [];
    if (!items.length) {
      if (db) {
        const cartItems = await db.collection("cart").find({ user: req.user.email }).toArray();
        items = cartItems.map((c) => ({ productId: c.productId, quantity: Number(c.quantity || 1) }));
      } else {
        const list = Array.isArray(carts[req.user.email]) ? carts[req.user.email] : [];
        items = list.map((c) => ({ productId: c.productId, quantity: Number(c.quantity || 1) }));
      }
    }
    if (!items.length) return res.status(400).json({ error: "Cart is empty" });
    const enriched = items.map((it) => {
      const p = products.find((x) => x.id === it.productId) || {};
      return {
        productId: it.productId,
        quantity: it.quantity,
        price: Number(p.price || 0),
        name: p.name || "",
        image: (p.images || [])[0] || "",
        progress: { placed: Date.now() },
      };
    });
    const order = { id: String(Date.now()), user: req.user.email, items: enriched, status: "placed", createdAt: Date.now(), shipping: lastCheckout[req.user.email] || null };
    if (db) {
      await db.collection("orders").insertOne(order);
      await db.collection("cart").deleteMany({ user: req.user.email });
    } else {
      const list = Array.isArray(orders[req.user.email]) ? orders[req.user.email] : [];
      orders[req.user.email] = [order, ...list];
      saveOrdersToFile();
      carts[req.user.email] = [];
      saveCartsToFile();
    }
    res.json(order);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
// Admin per-item stage update
app.put("/api/admin/orders/:id/item/:pid", authMiddleware, adminOnly, async (req, res) => {
  try {
    const id = req.params.id;
    const pid = req.params.pid;
    const { stage } = req.body || {};
    const valid = new Set(["placed", "dispatched", "in_transit", "shipped", "out_for_delivery", "delivered"]);
    if (!stage || !valid.has(stage)) return res.status(400).json({ error: "invalid stage" });
    if (db) {
      const order = await db.collection("orders").findOne({ $or: [{ id }, { _id: id }] });
      if (!order) return res.status(404).json({ error: "Not found" });
      const items = Array.isArray(order.items) ? order.items : [];
      const idx = items.findIndex((it) => it.productId === pid);
      if (idx === -1) return res.status(404).json({ error: "Item not found" });
      const progress = items[idx].progress || {};
      progress[stage] = Date.now();
      items[idx].progress = progress;
      const nextStatus = ["placed", "dispatched", "in_transit", "shipped", "out_for_delivery", "delivered"].findLast((s) => progress[s]);
      await db.collection("orders").updateOne({ $or: [{ id }, { _id: id }] }, { $set: { items, status: nextStatus || order.status } });
      return res.json({ success: true });
    }
    let found = false;
    for (const email of Object.keys(orders)) {
      const list = Array.isArray(orders[email]) ? orders[email] : [];
      const oIdx = list.findIndex((o) => o.id === id);
      if (oIdx >= 0) {
        const items = Array.isArray(list[oIdx].items) ? list[oIdx].items : [];
        const iIdx = items.findIndex((it) => it.productId === pid);
        if (iIdx === -1) break;
        const progress = items[iIdx].progress || {};
        progress[stage] = Date.now();
        items[iIdx].progress = progress;
        const nextStatus = ["placed", "dispatched", "in_transit", "shipped", "out_for_delivery", "delivered"].findLast((s) => progress[s]);
        list[oIdx].items = items;
        list[oIdx].status = nextStatus || list[oIdx].status;
        orders[email] = list;
        saveOrdersToFile();
        found = true;
        break;
      }
    }
    if (!found) return res.status(404).json({ error: "Not found" });
    res.json({ success: true, order });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.get("/api/wishlist", authMiddleware, async (req, res) => {
  try {
    if (db) {
      const items = await db.collection("wishlist").find({ user: req.user.email }).toArray();
      const ids = items.map((i) => i.productId);
      const productsList = await db.collection("products").find({ id: { $in: ids } }).toArray();
      return res.json(productsList);
    }
    const list = Array.isArray(wishlists[req.user.email]) ? wishlists[req.user.email] : [];
    const ids = new Set(list.map((i) => i.productId));
    const result = products.filter((p) => ids.has(p.id));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.post("/api/wishlist", authMiddleware, async (req, res) => {
  try {
    const { productId } = req.body || {};
    if (!productId) return res.status(400).json({ error: "productId required" });
    if (db) {
      const exists = await db.collection("wishlist").findOne({ user: req.user.email, productId });
      if (exists) return res.json({ success: true });
      await db.collection("wishlist").insertOne({ user: req.user.email, productId });
      return res.json({ success: true });
    }
    const list = Array.isArray(wishlists[req.user.email]) ? wishlists[req.user.email] : [];
    if (!list.find((i) => i.productId === productId)) list.push({ productId });
    wishlists[req.user.email] = list;
    saveWishlistsToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.delete("/api/wishlist", authMiddleware, async (req, res) => {
  try {
    const productId = (req.query.productId || "").toString();
    const all = (req.query.all || "").toString();
    if (db) {
      if (all) {
        await db.collection("wishlist").deleteMany({ user: req.user.email });
        return res.json({ success: true });
      }
      if (!productId) return res.status(400).json({ error: "productId required" });
      await db.collection("wishlist").deleteOne({ user: req.user.email, productId });
      return res.json({ success: true });
    }
    if (all) {
      wishlists[req.user.email] = [];
      saveWishlistsToFile();
      return res.json({ success: true });
    }
    if (!productId) return res.status(400).json({ error: "productId required" });
    const list = Array.isArray(wishlists[req.user.email]) ? wishlists[req.user.email] : [];
    wishlists[req.user.email] = list.filter((i) => i.productId !== productId);
    saveWishlistsToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
// Category Tiles API
app.get("/api/category-tiles", async (req, res) => {
  try {
    if (db) {
      const list = await db.collection("category_tiles").find({}).sort({ position: 1 }).limit(6).toArray();
      return res.json(list.map((x) => ({ category: x.category, image: x.image, position: Number(x.position ?? 0) })));
    }
    const entries = Object.entries(categoryTiles)
      .map(([pos, obj]) => ({ position: Number(pos), category: obj?.category || "", image: obj?.image || "" }))
      .sort((a, b) => a.position - b.position)
      .slice(0, 6)
      .map((e) => {
        try {
          if (e.image && e.image.startsWith("/uploads/")) {
            const lp = resolveLocal(e.image);
            let exists = false;
            try { exists = Boolean(lp && fs.existsSync(lp)); } catch {}
            if (!exists) {
              const full = path.basename(e.image || "");
              const stripped = full.includes("_") ? full.split("_").slice(1).join("_") : full;
              e.image = `/images/${stripped}`;
            }
          }
        } catch {}
        return e;
      });
    res.json(entries);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.post("/api/category-tiles", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { category, image, position } = req.body || {};
    const pos = Number(position);
    if (!category || !image || Number.isNaN(pos)) return res.status(400).json({ error: "category, image, position required" });
    if (pos < 0 || pos > 5) return res.status(400).json({ error: "position must be 0-5" });
    if (db) {
      await db.collection("category_tiles").updateOne({ position: pos }, { $set: { position: pos, category, image } }, { upsert: true });
      return res.json({ success: true });
    }
    categoryTiles[String(pos)] = { category, image };
    saveCategoryTilesToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.delete("/api/category-tiles", authMiddleware, adminOnly, async (req, res) => {
  try {
    const category = (req.query.category || "").toString();
    const position = req.query.position !== undefined ? Number(req.query.position) : undefined;
    if (!category && (position === undefined || Number.isNaN(position))) return res.status(400).json({ error: "category or position required" });
    if (db) {
      if (position !== undefined && !Number.isNaN(position)) {
        await db.collection("category_tiles").deleteOne({ position });
      } else {
        await db.collection("category_tiles").deleteOne({ category });
      }
      return res.json({ success: true });
    }
    if (position !== undefined && !Number.isNaN(position)) {
      delete categoryTiles[String(position)];
    } else {
      const key = Object.entries(categoryTiles).find(([_, v]) => v?.category === category)?.[0];
      if (key) delete categoryTiles[key];
    }
    saveCategoryTilesToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.post("/api/admin/category-tiles/migrate", authMiddleware, adminOnly, async (req, res) => {
  try {
    if (!hasS3 || !s3) return res.status(400).json({ error: "S3 not configured" });
    let updated = 0;
    let errors = [];
    function findLocalForImage(img) {
      try {
        const full = path.basename(img || "");
        const parts = full.split("_");
        const stripped = parts.length > 1 ? parts.slice(1).join("_") : full;
        const candidates = [
          path.join(uploadDir, full),
          path.join(path.resolve(__dirname, ".."), "uploads", full),
          path.join(path.resolve(__dirname, ".."), "frontend", "public", "uploads", full),
          path.join(path.resolve(__dirname, ".."), "frontend", "public", "images", full),
          path.join(path.resolve(__dirname, ".."), "frontend", "public", "images", stripped),
        ];
        for (const c of candidates) { try { if (fs.existsSync(c)) return c; } catch {} }
      } catch {}
      return null;
    }
    if (db) {
      const docs = await db.collection("category_tiles").find({}).toArray();
      for (const d of docs) {
        try {
          const lp = findLocalForImage(d.image) || resolveLocal(d.image);
          if (lp) {
            const url = await uploadLocalPath(lp, path.basename(d.image));
            if (url) {
              await db.collection("category_tiles").updateOne({ _id: d._id }, { $set: { image: url } });
              updated++;
            }
          }
        } catch (e) {
          errors.push({ category: d.category, image: d.image, error: String(e?.message || e) });
        }
      }
    } else {
      for (const [pos, obj] of Object.entries(categoryTiles)) {
        try {
          const lp = findLocalForImage(obj?.image || "") || resolveLocal(obj?.image || "");
          if (lp) {
            const url = await uploadLocalPath(lp, path.basename(obj.image));
            if (url) {
              categoryTiles[String(pos)] = { ...(obj || {}), image: url };
              updated++;
            }
          }
        } catch (e) {
          errors.push({ position: pos, category: obj?.category, image: obj?.image, error: String(e?.message || e) });
        }
      }
      saveCategoryTilesToFile();
    }
    res.json({ success: true, updated, errors });
  } catch (e) {
    res.status(500).json({ error: "Migration failed" });
  }
});
app.post("/api/products/:id/reviews", authMiddleware, async (req, res) => {
  try {
    const productId = req.params.id;
    const { rating, comment, images } = req.body || {};
    const r = Number(rating);
    if (!productId || !r || r < 1 || r > 5) return res.status(400).json({ error: "invalid rating" });
    let purchased = false;
    if (db) {
      const found = await db.collection("orders").findOne({ user: req.user.email, items: { $elemMatch: { productId } } });
      purchased = Boolean(found);
    } else {
      const list = Array.isArray(orders[req.user.email]) ? orders[req.user.email] : [];
      purchased = list.some((o) => (o.items || []).some((it) => it.productId === productId));
    }
    if (!purchased) return res.status(403).json({ error: "Not allowed" });
    if (db) {
      const p = await db.collection("products").findOne({ id: productId });
      if (!p) return res.status(404).json({ error: "Not found" });
      const review = { id: String(Date.now()), author: req.user.email, rating: r, comment: String(comment || ""), date: new Date().toISOString().slice(0,10), images: Array.isArray(images) ? images.slice(0,3) : [] };
      const nextReviews = Array.isArray(p.reviews) ? [...p.reviews, review] : [review];
      const nextRating = nextReviews.length ? Number((nextReviews.reduce((s, a) => s + Number(a.rating || 0), 0) / nextReviews.length).toFixed(1)) : 0;
      await db.collection("products").updateOne({ id: productId }, { $set: { reviews: nextReviews, rating: nextRating } });
      return res.json(review);
    }
    const p = products.find((x) => x.id === productId);
    if (!p) return res.status(404).json({ error: "Not found" });
    const review = { id: String(Date.now()), author: req.user.email, rating: r, comment: String(comment || ""), date: new Date().toISOString().slice(0,10), images: Array.isArray(images) ? images.slice(0,3) : [] };
    p.reviews = Array.isArray(p.reviews) ? [...p.reviews, review] : [review];
    p.rating = p.reviews.length ? Number((p.reviews.reduce((s, a) => s + Number(a.rating || 0), 0) / p.reviews.length).toFixed(1)) : 0;
    saveProductsToFile();
    res.json(review);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});

// Admin Orders APIs
app.get("/api/admin/orders", authMiddleware, adminOnly, async (req, res) => {
  try {
    if (db) {
      const list = await db.collection("orders").find({}).sort({ createdAt: -1 }).toArray();
      return res.json(list.map((o) => ({ id: o.id || String(o._id), user: o.user, items: o.items || [], status: o.status || "placed", createdAt: o.createdAt || Date.now() })));
    }
    const arr = Object.entries(orders).flatMap(([email, list]) => (Array.isArray(list) ? list.map((o) => ({ ...o, user: email })) : []));
    arr.sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
    res.json(arr);
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.get("/api/admin/orders/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const id = req.params.id;
    if (db) {
      const o = await db.collection("orders").findOne({ $or: [{ id }, { _id: id }] });
      if (!o) return res.status(404).json({ error: "Not found" });
      return res.json({ id: o.id || String(o._id), user: o.user, items: o.items || [], status: o.status || "placed", createdAt: o.createdAt || Date.now() });
    }
    for (const email of Object.keys(orders)) {
      const list = Array.isArray(orders[email]) ? orders[email] : [];
      const o = list.find((x) => x.id === id);
      if (o) return res.json({ ...o, user: email });
    }
    res.status(404).json({ error: "Not found" });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.put("/api/admin/orders/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const id = req.params.id;
    const { status } = req.body || {};
    if (!status) return res.status(400).json({ error: "status required" });
    if (db) {
      const r = await db.collection("orders").updateOne({ $or: [{ id }, { _id: id }] }, { $set: { status } });
      if (!r.matchedCount) return res.status(404).json({ error: "Not found" });
      return res.json({ success: true });
    }
    let updated = false;
    for (const email of Object.keys(orders)) {
      const list = Array.isArray(orders[email]) ? orders[email] : [];
      const idx = list.findIndex((o) => o.id === id);
      if (idx >= 0) { list[idx].status = status; orders[email] = list; updated = true; break; }
    }
    if (!updated) return res.status(404).json({ error: "Not found" });
    saveOrdersToFile();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed" });
  }
});
app.post("/api/admin/migrate-uploads", authMiddleware, adminOnly, async (req, res) => {
  try {
    if (!hasS3 || !s3) return res.status(400).json({ error: "S3 not configured" });
    let count = 0;
    let uploadedKeys = [];
    let errors = [];
    try {
      function walk(dir) {
        const out = [];
        try {
          for (const d of fs.readdirSync(dir, { withFileTypes: true })) {
            const p = path.join(dir, d.name);
            if (d.isDirectory()) out.push(...walk(p)); else if (d.isFile()) out.push(p);
          }
        } catch {}
        return out;
      }
      const roots = [
        uploadDir,
        path.join(path.resolve(__dirname, ".."), "uploads"),
        path.join(path.resolve(__dirname, ".."), "frontend", "public", "uploads"),
        path.join(path.resolve(__dirname, ".."), "frontend", "public", "images"),
      ];
      for (const root of roots) {
        for (const lp of walk(root)) {
          try {
            const url = await uploadLocalPath(lp, path.basename(lp));
            if (url) { count++; uploadedKeys.push(url); } else { errors.push({ file: lp, error: "upload-failed" }); }
          } catch (e) {
            errors.push({ file: lp, error: String(e?.message || e) });
          }
        }
      }
    } catch {}
    res.json({ success: true, count, urls: uploadedKeys, errors });
  } catch (e) {
    res.status(500).json({ error: "Migration failed" });
  }
});