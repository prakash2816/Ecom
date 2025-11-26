import express from "express";

export default function register({ app, getDb, authMiddleware, adminOnly, getSubcategories, saveSubcategories }) {
  const router = express.Router();

  router.get("/", async (req, res) => {
    try {
      const category = (req.query.category || "").toString();
      if (!category) return res.status(400).json({ error: "category required" });
      const db = getDb();
      if (db) {
        const list = await db.collection("subcategories").find({ category }).toArray();
        return res.json(list.map((s) => s.name));
      }
      const list = getSubcategories()[category] || [];
      return res.json(list);
    } catch (e) {
      res.status(500).json({ error: "Failed" });
    }
  });

  router.post("/", authMiddleware, adminOnly, async (req, res) => {
    try {
      const { category, name } = req.body || {};
      if (!category || !name) return res.status(400).json({ error: "category and name required" });
      const db = getDb();
      if (db) {
        const exists = await db.collection("subcategories").findOne({ category, name });
        if (exists) return res.json({ success: true });
        await db.collection("subcategories").insertOne({ category, name });
        return res.json({ success: true });
      }
      const subs = getSubcategories();
      const list = subs[category] || [];
      if (!list.includes(name)) {
        subs[category] = [...list, name];
        saveSubcategories();
      }
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed" });
    }
  });

  router.put("/", authMiddleware, adminOnly, async (req, res) => {
    try {
      const { category, oldName, newName } = req.body || {};
      if (!category || !oldName || !newName) return res.status(400).json({ error: "category, oldName, newName required" });
      const db = getDb();
      if (db) {
        const r = await db.collection("subcategories").updateOne({ category, name: oldName }, { $set: { name: newName } });
        if (!r.matchedCount) return res.status(404).json({ error: "Not found" });
        return res.json({ success: true });
      }
      const subs = getSubcategories();
      const list = subs[category] || [];
      const idx = list.findIndex((n) => n === oldName);
      if (idx === -1) return res.status(404).json({ error: "Not found" });
      list[idx] = newName;
      subs[category] = list;
      saveSubcategories();
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed" });
    }
  });

  router.delete("/", authMiddleware, adminOnly, async (req, res) => {
    try {
      const body = req.body || {};
      const qCategory = (req.query?.category || "").toString();
      const qName = (req.query?.name || "").toString();
      const category = body.category || qCategory;
      const name = body.name || qName;
      if (!category || !name) return res.status(400).json({ error: "category, name required" });
      const db = getDb();
      if (db) {
        await db.collection("subcategories").deleteOne({ category, name });
        return res.json({ success: true });
      }
      const subs = getSubcategories();
      const list = subs[category] || [];
      subs[category] = list.filter((n) => n !== name);
      saveSubcategories();
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed" });
    }
  });

  app.use("/api/subcategories", router);
}