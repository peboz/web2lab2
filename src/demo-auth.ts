const accountPin = "1506";
export const failureLimit = 3;
export const lockSeconds = 60;
const failureWindow = 60_000;

let failures = 0;
let failureWindowEnds = 0;
let lockedUntil = 0;

type Attempt = {
  pin: string;
  outcome: "denied" | "granted" | "locked";
  retryAfter?: number;
};

export function verifyPin(pin: string, vulnerable: boolean): Attempt {
  if (vulnerable) {
    return { pin, outcome: pin === accountPin ? "granted" : "denied" };
  }

  const now = Date.now();
  if (now < lockedUntil) {
    return { pin, outcome: "locked", retryAfter: Math.ceil((lockedUntil - now) / 1000) };
  }

  if (pin === accountPin) {
    failures = 0;
    return { pin, outcome: "granted" };
  }

  if (failures === 0 || now >= failureWindowEnds) {
    failures = 0;
    failureWindowEnds = now + failureWindow;
  }
  failures++;

  if (failures === failureLimit) {
    failures = 0;
    lockedUntil = now + lockSeconds * 1000;
    return { pin, outcome: "denied", retryAfter: lockSeconds };
  }

  return { pin, outcome: "denied" };
}

export function guessPin(vulnerable: boolean): Attempt[] {
  const attempts: Attempt[] = [];
  for (let candidate = 0; candidate < 10000; candidate++) {
    const pin = String(candidate).padStart(4, "0");
    const attempt = verifyPin(pin, vulnerable);
    attempts.push(attempt);
    if (attempt.outcome !== "denied" || attempt.retryAfter !== undefined) break;
  }
  return attempts;
}
