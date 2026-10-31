import { exec, execFile } from "node:child_process";
import { Router } from "express";

const router = Router();

router.post("/parcels/convert", (req, res) => {
  const source = String(req.body.path ?? "");
  exec(`convert ${source} preview.pdf`, (_error, stdout) => {
    res.send(stdout);
  });
});

router.post("/parcels/convert-file", (req, res) => {
  const source = String(req.body.path ?? "");
  execFile("convert", [source, "preview.pdf"], (_error, stdout) => {
    res.send(stdout);
  });
});

router.post("/notes/formula", (req, res) => {
  const formula = String(req.body.formula ?? "");
  const value = eval(formula);
  res.json({ value });
});

router.post("/notes/total", (req, res) => {
  const field = String(req.body.field ?? "");
  const allowlist = ["weight", "postage"];
  const picked = allowlist.includes(field) ? field : "weight";
  const value = eval(picked);
  res.json({ value });
});

export { router as tools };
