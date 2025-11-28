import express from "express";

export default function register({ app, getDb, authMiddleware, adminOnly, getCarousel, setCarousel, saveCarousel }) {
  const router = express.Router();

  router.get("/", async (req, res) => {
    try {
      const db = getDb();
      if (db) {
        const doc = await db.collection("carousel").findOne({ _id: "default" });
        return res.json(Array.isArray(doc?.images) ? doc.images.slice(0,5) : []);
      }
      const arr = getCarousel();
      res.json(Array.isArray(arr) ? arr.slice(0,5) : []);
    } catch (e) {
      res.status(500).json({ error: "Failed" });
    }
  });

  router.post("/", authMiddleware, adminOnly, async (req, res) => {
    try {
      const { images } = req.body || {};
      const list = Array.isArray(images) ? images.filter((u) => typeof u === "string").slice(0,5) : [];
      const db = getDb();
      if (db) {
        await db.collection("carousel").updateOne({ _id: "default" }, { $set: { images: list } }, { upsert: true });
        return res.json({ success: true });
      }
      setCarousel(list);
      saveCarousel();
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed" });
    }
  });

  app.use("/api/carousel", router);
}