// Outbound HTTP through a client other than fetch. Not a server. CI does not run it.
import express from "express";

const needle = {
  get(_url: string, done: () => void): void {
    done();
  },
};

const app = express();

app.get("/quote", (req, res) => {
  const url = String(req.query.url ?? "") + String(req.query.symbol ?? "");
  needle.get(url, () => {
    res.end();
  });
});

app.get("/health", (_req, res) => {
  needle.get("https://example.com/health", () => {
    res.end();
  });
});

export { app };
