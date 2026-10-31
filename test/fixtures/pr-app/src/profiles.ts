// Seeded fixture. Not a server. CI does not run it.
import express from "express";
import { prisma } from "./db.js";

const router = express.Router();

router.get("/profiles/:id", async (req, res) => {
  const profile = await prisma.profile.findUnique({
    where: { id: req.params.id },
  });
  res.json(profile);
});

export { router };
