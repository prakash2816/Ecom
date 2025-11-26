import express from "express";

export default function register({ app, getDb, authMiddleware, adminOnly, getCategories, setCategories, getSubcategories, saveCategories, saveSubcategories }) {
  const router = express.Router();

  router.get("/", async (req, res) => {
    try {
      const db = getDb();
      if (db) {
        const cats = await db.collection("categories").find({}).toArray();
        const catNames = cats.map((c) => c.name);
        const subcats = await db.collection("subcategories").find({}).toArray();
        const dbSubNames = new Set(subcats.map((s) => s.name));
        const fileSubNames = new Set(Object.values(getSubcategories()).flat());
        const allSubNames = new Set([...dbSubNames, ...fileSubNames]);
        const filtered = catNames.filter((name) => !allSubNames.has(name));
        return res.json(filtered);
      }
      const allSubNames = new Set(Object.values(getSubcategories()).flat());
      const filtered = getCategories().filter((name) => !allSubNames.has(name));
      return res.json(filtered);
    } catch (e) {
      res.status(500).json({ error: "Failed" });
    }
  });

  router.post("/", authMiddleware, adminOnly, async (req, res) => {
    try {
      const { name } = req.body || {};
      if (!name) return res.status(400).json({ error: "Name required" });
      const db = getDb();
      if (db) {
        const exists = await db.collection("categories").findOne({ name });
        if (exists) return res.json({ success: true });
        await db.collection("categories").insertOne({ name });
        return res.json({ success: true });
      }
      const cats = getCategories();
      if (!cats.includes(name)) {
        setCategories([...cats, name]);
        saveCategories();
      }
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed" });
    }
  });

  router.put("/", authMiddleware, adminOnly, async (req, res) => {
    try {
      const { oldName, newName } = req.body || {};
      if (!oldName || !newName) return res.status(400).json({ error: "oldName and newName required" });
      const db = getDb();
      if (db) {
        const exists = await db.collection("categories").findOne({ name: oldName });
        if (!exists) return res.status(404).json({ error: "Not found" });
        await db.collection("categories").updateOne({ name: oldName }, { $set: { name: newName } });
        await db.collection("subcategories").updateMany({ category: oldName }, { $set: { category: newName } });
        return res.json({ success: true });
      }
      const cats = getCategories();
      const idx = cats.findIndex((c) => c === oldName);
      if (idx === -1) return res.status(404).json({ error: "Not found" });
      cats[idx] = newName;
      const subs = getSubcategories();
      if (subs[oldName]) {
        subs[newName] = subs[oldName];
        delete subs[oldName];
      }
      setCategories(cats);
      saveCategories();
      saveSubcategories();
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed" });
    }
  });

  router.delete("/", authMiddleware, adminOnly, async (req, res) => {
    try {
      const body = req.body || {};
      const queryName = (req.query?.name || "").toString();
      const name = body.name || queryName;
      if (!name) return res.status(400).json({ error: "Name required" });
      const db = getDb();
      if (db) {
        await db.collection("categories").deleteOne({ name });
        await db.collection("subcategories").deleteMany({ category: name });
        return res.json({ success: true });
      }
      const cats = getCategories().filter((c) => c !== name);
      const subs = getSubcategories();
      if (subs[name]) delete subs[name];
      setCategories(cats);
      saveCategories();
      saveSubcategories();
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed" });
    }
  });

  app.use("/api/categories", router);
}