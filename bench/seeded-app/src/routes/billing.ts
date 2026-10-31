import { Router } from "express";
import { ensureTenant, requireAuth } from "../auth.js";
import { prisma } from "../db.js";

const router = Router();
router.use(requireAuth);

router.get("/invoices/:invoiceId", async (req, res) => {
  const invoice = await prisma.invoice.findOne({ id: req.params.invoiceId });
  res.json(invoice);
});

router.get("/invoices/:invoiceId/tenant", async (req, res) => {
  const invoice = await prisma.invoice.findOne({ id: req.params.invoiceId });
  ensureTenant(req.user.tenantId, invoice.tenantId);
  res.json(invoice);
});

export { router as billing };
