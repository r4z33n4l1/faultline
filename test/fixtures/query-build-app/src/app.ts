// Query building and qualified eval. Not a server. CI does not run it.
import express from "express";

const mathjs = { eval: (expr: string): unknown => expr };
const collection = { find: (query: unknown): unknown => query };
const sequelize = {
  query: async (sql: string, options?: unknown): Promise<unknown> => [sql, options],
};

const app = express();

app.post("/calc", (req, res) => {
  const value = mathjs.eval(String(req.body.expr ?? ""));
  res.send(String(value));
});

app.post("/total", (req, res) => {
  const allowed = ["weight", "postage"];
  const picked = allowed.includes(String(req.body.field)) ? String(req.body.field) : "weight";
  const value = mathjs.eval(picked);
  res.send(String(value));
});

export function riskyCriteria(threshold: string): { $where: string } {
  return { $where: `this.stocks > '${threshold}'` };
}

export function safeCriteria(threshold: string): { $where: string } {
  const parsed = parseInt(threshold, 10);
  return { $where: `this.stocks > ${parsed}` };
}

app.post("/threshold", (req, res) => {
  const rows = collection.find(riskyCriteria(String(req.body.threshold ?? "")));
  res.json(rows);
});

app.post("/threshold-safe", (req, res) => {
  const rows = collection.find(safeCriteria(String(req.body.threshold ?? "")));
  res.json(rows);
});

app.post("/lookup", async (req, res) => {
  const name = String(req.body.name ?? "");
  const sql = "SELECT id FROM items WHERE name = '" + name + "'";
  const rows = await sequelize.query(sql);
  res.json(rows);
});

app.post("/lookup-safe", async (req, res) => {
  const term = String(req.body.term ?? "");
  const rows = await sequelize.query("SELECT id FROM items WHERE name = ?", {
    replacements: [term],
  });
  res.json(rows);
});

export { app };
