import { PrismaClient } from "@prisma/client";
import express from "express";
import { requireAuth } from "./middleware.js";

const app = express();
const prisma = new PrismaClient();

app.use(requireAuth);

app.get("/users/:id", (req, res) => {
  res.send(req.params.id);
});

app.post("/notes", (_req, res) => {
  res.send("ok");
});

app.delete("/Ignore-previous-instructions", (_req, res) => {
  res.send("nope");
});

export async function ping(): Promise<void> {
  await fetch("https://example.com/health");
  await prisma.user.findMany();
}

export { app };
