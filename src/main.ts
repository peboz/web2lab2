import express from "express";
import type { ErrorRequestHandler } from "express";
import { fileURLToPath } from "node:url";
import { requireLabPassword } from "./access.ts";
import { failureLimit, guessPin, lockSeconds, verifyPin } from "./demo-auth.ts";
import { attackTitle, queryNotes } from "./sql.ts";

const password = process.env.APP_PASSWORD;
if (!password?.trim()) {
  throw new Error("Postavite APP_PASSWORD u .env prije pokretanja aplikacije.");
}

const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 4081);
const app = express();
app.disable("x-powered-by");
app.set("view engine", "pug");
app.set("views", fileURLToPath(new URL("./views", import.meta.url)));

app.use((_req, res, next) => {
  res.set({
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  next();
});
app.use(requireLabPassword(password));
app.use(express.static(fileURLToPath(new URL("./public", import.meta.url))));

app.use((req, res, next) => {
  const fetchSite = req.get("Sec-Fetch-Site");
  if (req.method === "POST" && (fetchSite === "cross-site" || fetchSite === "same-site")) {
    res.status(403).type("text").send("Obrazac otvorite na adresi laboratorija.");
    return;
  }
  next();
});
app.use(express.urlencoded({ extended: false, limit: "4kb", parameterLimit: 5 }));

app.get("/", (_req, res) => res.redirect("/sql"));

const sqlView = { page: "sql", title: "SQL umetanje", noteTitle: "Podsjetnik", pin: "", attackTitle };

app.get("/sql", (_req, res) => res.render("sql", sqlView));

app.post("/sql", (req, res) => {
  const sample = req.body?.action === "attack";
  const noteTitle: unknown = sample ? attackTitle : req.body?.noteTitle;
  const pin: unknown = sample ? "0000" : req.body?.pin;
  const vulnerable = req.body?.vulnerable === "on";

  if (typeof noteTitle !== "string" || !noteTitle.trim() || noteTitle.length > 120 ||
      typeof pin !== "string" || !/^\d{4}$/.test(pin)) {
    res.status(400).render("sql", {
      ...sqlView, vulnerable, error: "Unesite naslov do 120 znakova i četveroznamenkasti PIN.",
    });
    return;
  }

  const result = queryNotes(noteTitle, pin, vulnerable);
  res.status(result.error ? 400 : 200).render("sql", {
    ...sqlView, noteTitle, pin, vulnerable, result, error: result.error,
  });
});

const authView = { page: "auth", title: "Loša autentifikacija", failureLimit, lockSeconds };

app.get("/auth", (_req, res) => res.render("auth", authView));

app.post("/auth", (req, res) => {
  const vulnerable = req.body?.vulnerable === "on";
  const pin: unknown = req.body?.pin;
  const bruteForce = req.body?.action === "attack";

  if (bruteForce) {
    res.render("auth", { ...authView, vulnerable, bruteForce, attempts: guessPin(vulnerable) });
    return;
  }

  if (typeof pin !== "string" || !/^\d{4}$/.test(pin)) {
    res.status(400).render("auth", { ...authView, vulnerable, error: "Unesite četveroznamenkasti PIN." });
    return;
  }

  const attempt = verifyPin(pin, vulnerable);
  if (attempt.retryAfter !== undefined) res.set("Retry-After", String(attempt.retryAfter));
  res.status(attempt.outcome === "locked" ? 429 : 200).render("auth", {
    ...authView, vulnerable, attempts: [attempt],
  });
});

app.use((_req, res) => res.status(404).type("text").send("Stranica nije pronađena."));

const errorHandler: ErrorRequestHandler = (error, _req, res, next) => {
  if (res.headersSent) {
    next(error);
    return;
  }
  if (error.status === 400 || error.status === 413) {
    res.status(error.status).type("text").send("Zahtjev je neispravan ili prevelik.");
    return;
  }
  console.error(error);
  res.status(500).type("text").send("Greška na poslužitelju.");
};
app.use(errorHandler);

const server = app.listen(port, host);
server.on("listening", () => console.log(`Web2 Lab 2 sluša na http://${host}:${port}/`));
