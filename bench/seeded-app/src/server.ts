import express from "express";
import { billing } from "./routes/billing.js";
import { documents } from "./routes/documents.js";
import { remote } from "./routes/remote.js";
import { search } from "./routes/search.js";
import { shareAdmin } from "./routes/share-admin.js";
import { shares } from "./routes/shares.js";
import { tools } from "./routes/tools.js";
import { openDeskSession } from "./credentials.js";

const app = express();
app.use(express.json());
app.use(billing);
app.use(documents);
app.use(shares);
app.use(shareAdmin);
app.use(search);
app.use(tools);
app.use(remote);

app.get("/health", (_req, res) => {
  res.json({ ok: true, session: openDeskSession().length > 0 });
});

export { app };
