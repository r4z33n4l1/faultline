// Generic Express handlers referenced by name. Not a server. CI does not run it.
import express from "express";
import { listMine, listPeople } from "./people.js";
import { Records } from "./records.js";

function requireUser(_req: unknown, _res: unknown, next: () => void): void {
  next();
}

function requireAdmin(_req: unknown, _res: unknown, next: () => void): void {
  next();
}

const records = new Records();
const router = express.Router();

router
  .route("/records/:recordId")
  .get(requireUser, records.read)
  .delete(requireUser, requireAdmin, records.remove);

router.get("/people", requireUser, listPeople);
router.get("/mine", requireUser, listMine);

export { router };
