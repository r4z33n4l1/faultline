import { Router } from "express";
import { requireAuth, requireOwner } from "../auth.js";
import { prisma } from "../db.js";

const router = Router();
router.use(requireAuth);

router.delete("/shares/:shareId", async (req, res) => {
  requireOwner(req.user.id, req.params.shareId);
  const share = await prisma.share.findUnique({ where: { id: req.params.shareId } });
  res.json({ deleted: share !== undefined });
});

export { router as shareAdmin };
