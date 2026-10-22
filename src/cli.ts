#!/usr/bin/env node
import crypto from "node:crypto";
import { startProxy } from "./adapters/proxy.js";
import { NETWORK_USDC } from "./protocol.js";

// ---------------------------------------------------------------------------
// furlpay-gateway — put a stablecoin paywall in front of anything, in one line.
//
//   furlpay-gateway expose http://localhost:8000 --price 0.01 --pay-to 0xabc...
//   furlpay-gateway secret
// ---------------------------------------------------------------------------

interface Flags {
  [key: string]: string | boolean;
}

function parseFlags(argv: string[]): { positional: string[]; flags: Flags } {
  const positional: string[] = [];
  const flags: Flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        flags[key] = true;
      } else {
        flags[key] = next;
        i++;
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

const USAGE = `
furlpay-gateway — x402 monetization gateway

USAGE
  furlpay-gateway expose <origin> [options]
  furlpay-gateway secret

COMMANDS
  expose <origin>   Paywall an origin and serve it on a public port.
  secret            Generate a quote secret.

OPTIONS (expose)
  --price <usd>          Price per call in USD.            (required)
  --pay-to <address>     Wallet that receives payment.     (required, or PAY_TO)
  --secret <hex>         Quote HMAC secret.                (or QUOTE_SECRET)
  --network <name>       ${Object.keys(NETWORK_USDC).join(", ")}   (default: base)
  --port <n>             Listen port.                      (default: 4402)
  --facilitator <url>    x402 facilitator.                 (default: FurlPay)
  --free <paths>         Comma-separated free paths, e.g. /health,/docs/*
  --public-url <url>     Public base URL if behind TLS termination.
  --no-settle            Verify only; do not settle on-chain. (unsafe)

ENVIRONMENT
  PAY_TO, QUOTE_SECRET, FURLPAY_FACILITATOR

EXAMPLE
  furlpay-gateway secret
  export QUOTE_SECRET=<the value it printed>
  furlpay-gateway expose http://localhost:8000 \\
    --price 0.01 --pay-to 0xYourWallet --network base --free /health

SECURITY
  The origin must NOT be publicly reachable, or agents will route around the
  paywall. Bind it to loopback or firewall it to this process.
`;

function die(msg: string): never {
  process.stderr.write(`error: ${msg}\n\nRun \`furlpay-gateway --help\` for usage.\n`);
  process.exit(1);
}

async function main(): Promise<void> {
  const { positional, flags } = parseFlags(process.argv.slice(2));
  const command = positional[0];

  if (!command || flags.help || flags.h) {
    process.stdout.write(USAGE);
    return;
  }

  if (command === "secret") {
    process.stdout.write(crypto.randomBytes(32).toString("hex") + "\n");
    return;
  }

  if (command !== "expose") die(`unknown command "${command}"`);

  const origin = positional[1];
  if (!origin) die("expose requires an origin, e.g. http://localhost:8000");
  if (!/^https?:\/\//.test(origin)) die(`origin must start with http:// or https:// (got "${origin}")`);

  const price = Number(flags.price);
  if (!Number.isFinite(price) || price <= 0) die("--price must be a positive number of USD");

  const payTo = (flags["pay-to"] as string) || process.env.PAY_TO;
  if (!payTo) die("--pay-to (or PAY_TO) is required — nobody gets paid otherwise");

  const quoteSecret = (flags.secret as string) || process.env.QUOTE_SECRET;
  if (!quoteSecret) {
    die("--secret (or QUOTE_SECRET) is required. Generate one: furlpay-gateway secret");
  }

  const network = (flags.network as string) || "base";
  if (!NETWORK_USDC[network]) {
    die(`unknown network "${network}" — one of: ${Object.keys(NETWORK_USDC).join(", ")}`);
  }

  const freePaths = typeof flags.free === "string" ? flags.free.split(",").map((s) => s.trim()) : [];
  const port = flags.port ? Number(flags.port) : 4402;
  const facilitator = (flags.facilitator as string) || process.env.FURLPAY_FACILITATOR;

  const running = await startProxy({
    origin,
    port,
    price,
    payTo,
    quoteSecret,
    network,
    freePaths,
    settle: flags["no-settle"] !== true,
    publicUrl: flags["public-url"] as string | undefined,
    ...(facilitator ? { facilitator } : {}),
    onSettled: (r) => {
      process.stdout.write(
        `paid  $${(Number(r.amountAtomic) / 1e6).toFixed(6)}  ${r.payer.slice(0, 10)}…  ${r.resource}\n`
      );
    },
  });

  const lines = [
    ``,
    `  FurlPay Gateway`,
    ``,
    `  paywalling   ${origin}`,
    `  listening    http://localhost:${running.port}`,
    `  price        $${price.toFixed(6)} per call`,
    `  pay to       ${payTo}`,
    `  network      ${network} (USDC ${NETWORK_USDC[network].slice(0, 10)}…)`,
    `  facilitator  ${facilitator ?? "furlpay.com (default)"}`,
    freePaths.length ? `  free         ${freePaths.join(", ")}` : ``,
    flags["no-settle"] === true ? `  WARNING      --no-settle: payments are verified but NOT collected` : ``,
    ``,
    `  Replay protection is in-memory: correct for ONE instance only.`,
    `  Run more than one and pass a shared claim store (see README).`,
    ``,
  ].filter(Boolean);
  process.stdout.write(lines.join("\n") + "\n");

  const shutdown = async () => {
    await running.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((e) => die((e as Error).message));
