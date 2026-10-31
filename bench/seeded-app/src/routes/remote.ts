import https from "node:https";
import axios from "axios";
import { Router } from "express";
import { hooks } from "../db.js";

const router = Router();
const allowedHosts = new Set(["cdn.parcel.test", "assets.parcel.test"]);

router.get("/parcels/remote", async (req, res) => {
  const target = String(req.query.url ?? "");
  const response = await fetch(target);
  res.status(response.status).send(await response.text());
});

router.post("/parcels/hook", async (req, res) => {
  const callbackUrl = String(req.body.callbackUrl ?? "");
  await hooks.insert({ callbackUrl });
  const response = await fetch(callbackUrl);
  res.json({ ok: response.ok });
});

router.get("/parcels/probe", (req, res) => {
  const host = String(req.query.host ?? "");
  https.get(`https://${host}/status`, (response) => {
    res.json({ status: response.statusCode });
  });
});

router.get("/parcels/import", async (req, res) => {
  const page = String(req.query.page ?? "");
  const response = await axios.get(page);
  res.send(response.data);
});

router.get("/parcels/asset", async (req, res) => {
  const target = new URL(String(req.query.url ?? ""));
  if (!allowedHosts.has(target.hostname)) {
    res.status(400).json({ error: "host" });
    return;
  }
  const response = await fetch(target);
  res.send(await response.text());
});

router.get("/parcels/mirror", async (req, res) => {
  const target = new URL(String(req.query.url ?? ""));
  if (target.hostname === "mirror.parcel.test") {
    const response = await fetch(target);
    res.send(await response.text());
    return;
  }
  res.status(400).end();
});

router.get("/parcels/label/:id", async (req, res) => {
  const id = encodeURIComponent(String(req.params.id ?? ""));
  const response = await fetch(`https://labels.parcel.test/v1/${id}`);
  res.send(await response.text());
});

router.get("/parcels/health", async (_req, res) => {
  const response = await fetch("https://status.parcel.test/health");
  res.send(await response.text());
});

export { router as remote };
