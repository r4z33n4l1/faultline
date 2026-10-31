import { Router } from "express";
import { assertOwner, requireAuth } from "../auth.js";
import { prisma } from "../db.js";

const router = Router();
router.use(requireAuth);

router.get("/documents/:documentId", async (req, res) => {
  const document = await prisma.document.findUnique({
    where: { id: req.params.documentId },
  });
  res.json(document);
});

router.get("/documents/:documentId/download", async (req, res) => {
  const document = await prisma.document.findUnique({
    where: { id: req.params.documentId, ownerId: req.user.id },
  });
  res.json(document);
});

router.get("/folders/:folderId", async (req, res) => {
  const folder = await prisma.folder.findById(req.params.folderId);
  res.json(folder);
});

router.patch("/folders/:folderId", async (req, res) => {
  assertOwner(req.user.id, req.params.folderId);
  const folder = await prisma.folder.findById(req.params.folderId);
  res.json(folder);
});

export { router as documents };
