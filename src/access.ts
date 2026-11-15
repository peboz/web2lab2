import { createHash, timingSafeEqual } from "node:crypto";
import type { RequestHandler } from "express";
import { rateLimit } from "express-rate-limit";

function digest(value: string | Buffer): Buffer {
  return createHash("sha256").update(value).digest();
}

export function requireLabPassword(password: string): RequestHandler {
  const expected = digest(`lab:${password}`);
  const limitFailures = rateLimit({
    windowMs: 60_000,
    limit: 10,
    standardHeaders: false,
    legacyHeaders: false,
    message: "Previše neuspjelih prijava. Pokušajte ponovno za minutu.",
    // za nginx reverse proxy na lokalnom deployu
    validate: { xForwardedForHeader: false },
  });

  return (req, res, next) => {
    const credentials = /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(
      req.get("Authorization") ?? "",
    );
    if (credentials) {
      const received = digest(Buffer.from(credentials[1], "base64"));
      if (timingSafeEqual(received, expected)) {
        next();
        return;
      }

      return limitFailures(req, res, challenge);
    }

    challenge();

    function challenge(error?: unknown): void {
      if (error) {
        next(error);
        return;
      }
      res.set("WWW-Authenticate", 'Basic realm="Web2 Lab 2", charset="UTF-8"');
      res.status(401).type("text").send("Unesite korisničko ime lab i zaporku za pristup demonstraciji labosa.");
    }
  };
}
