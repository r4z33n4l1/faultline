import { Router } from "express";
import { prisma } from "../db.js";

const router = Router();

router.post("/shares/:shareId", async (req, res) => {
  const share = await prisma.share.findUnique({ where: { id: req.params.shareId } });
  res.json(share);
});

export { router as shares };
