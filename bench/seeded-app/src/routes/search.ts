import { Router } from "express";
import { db, notes } from "../db.js";

const router = Router();

router.get("/notes/search", async (req, res) => {
  const title = String(req.query.q ?? "");
  const rows = await db.query(`SELECT id, title FROM notes WHERE title LIKE '%${title}%'`);
  res.json(rows);
});

router.get("/notes/find", async (req, res) => {
  const title = String(req.query.q ?? "");
  const rows = await db.query("SELECT id, title FROM notes WHERE title LIKE ?", [`%${title}%`]);
  res.json(rows);
});

router.get("/notes/sort", async (req, res) => {
  const sort = String(req.query.sort ?? "created_at");
  const allowlist = ["created_at", "title"];
  const column = allowlist.includes(sort) ? sort : "created_at";
  const rows = await db.query(`SELECT id, title FROM notes ORDER BY ${column}`);
  res.json(rows);
});

router.post("/notes/filter", async (req, res) => {
  const filter = req.body.filter;
  const rows = await notes.find({ $where: filter });
  res.json(rows);
});

export { router as search };
