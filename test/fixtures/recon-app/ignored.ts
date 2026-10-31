import express from "express";

const app = express();
app.get("/dummy-value-do-not-leak-9f3a2c", () => {});
export { app };
