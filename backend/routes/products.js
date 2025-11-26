import crypto from "crypto";
import express from "express";

export default function register({ app, getDb, authMiddleware, adminOnly, getProducts, setProducts, saveProducts, getCategories, saveCategories, getSubcategories }) {
  const router = express.Router();

  router.get("/", async (req, res) => {
    try {
      const db = getDb();
      if (db) {
        const items = await db.collection("products").find({}).sort({ createdAt: -1, _id: -1 }).toArray();
        const sanitized = items.map((p) => ({ ...p, images: Array.isArray(p.images) ? p.images.filter((u) => typeof u === "string" && u && !u.startsWith("blob:")) : [] }));
        return res.json(sanitized);
      }
      const products = getProducts();
      const sorted = [...products]
        .map((p) => ({ ...p, images: Array.isArray(p.images) ? p.images.filter((u) => typeof u === "string" && u && !u.startsWith("blob:")) : [] }))
        .sort((a, b) => (Number(b.createdAt || 0) - Number(a.createdAt || 0)));
      res.json(sorted);
    } catch (e) {
      res.status(500).json({ error: "Database error" });
    }
  });

  router.get("/:id", async (req, res) => {
    try {
      const db = getDb();
      if (db) {
        const item = await db.collection("products").findOne({ id: req.params.id });
        if (!item) return res.status(404).json({ error: "Not found" });
        const sanitized = { ...item, images: Array.isArray(item.images) ? item.images.filter((u) => typeof u === "string" && u && !u.startsWith("blob:")) : [] };
        return res.json(sanitized);
      }
      const products = getProducts();
      const item = products.find((p) => p.id === req.params.id);
      if (!item) return res.status(404).json({ error: "Not found" });
      const sanitized = { ...item, images: Array.isArray(item.images) ? item.images.filter((u) => typeof u === "string" && u && !u.startsWith("blob:")) : [] };
      res.json(sanitized);
    } catch (e) {
      res.status(500).json({ error: "Database error" });
    }
  });

  router.post("/", authMiddleware, adminOnly, async (req, res) => {
    try {
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
      const db = getDb();
      if (!db) {
        const products = getProducts();
        const sub = getSubcategories();
        const cats = getCategories();
        products.push(doc);
        if (doc.category) {
          const parent = Object.keys(sub).find((cat) => (sub[cat] || []).includes(doc.category)) || doc.category;
          if (!cats.includes(parent)) {
            cats.push(parent);
            saveCategories();
          }
        }
        saveProducts();
        return res.json({ success: true, id: doc.id });
      }
      await db.collection("products").insertOne(doc);
      res.json({ success: true, id: doc.id });
    } catch (e) {
      res.status(500).json({ error: "Create failed" });
    }
  });

  router.put("/:id", authMiddleware, adminOnly, async (req, res) => {
    try {
      const db = getDb();
      if (!db) {
        const id = req.params.id;
        const products = getProducts();
        const idx = products.findIndex((p) => p.id === id);
        if (idx === -1) return res.status(404).json({ error: "Not found" });
        products[idx] = { ...products[idx], ...req.body };
        setProducts(products);
        saveProducts();
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

  router.delete("/:id", authMiddleware, adminOnly, async (req, res) => {
    try {
      const db = getDb();
      if (!db) {
        const id = req.params.id;
        let products = getProducts();
        const before = products.length;
        products = products.filter((p) => p.id !== id);
        setProducts(products);
        saveProducts();
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

  app.use("/api/products", router);
}