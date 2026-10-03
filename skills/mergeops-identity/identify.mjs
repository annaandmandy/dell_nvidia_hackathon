#!/usr/bin/env node
// Identity lookup over roles.json (mirrors scripts/identity.py: identify / find_by_name).
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const roles = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "roles.json"), "utf8"),
);

function identify(slackId) {
  const user = roles.users[slackId];
  if (!user) return { known: false, slack_id: slackId };
  const company = roles.companies[user.company] ?? {};
  return {
    known: true,
    slack_id: slackId,
    ...user,
    company_name: company.name ?? user.company,
    company_emoji: company.emoji ?? ":bust_in_silhouette:",
  };
}

function findByName(query) {
  const q = query.trim().toLowerCase();
  if (roles.users[query.trim()]) return identify(query.trim());
  const hit = Object.entries(roles.users).find(([, u]) => u.name.toLowerCase().includes(q));
  return hit ? identify(hit[0]) : { known: false, query };
}

const [cmd, ...rest] = process.argv.slice(2);
const arg = rest.join(" ");
let out;
if (cmd === "id" && arg) out = identify(arg);
else if (cmd === "find" && arg) out = findByName(arg);
else if (cmd === "list") out = Object.keys(roles.users).map(identify);
else {
  console.error("usage: identify.mjs id <SLACK_ID> | find <name> | list");
  process.exit(2);
}
console.log(JSON.stringify(out, null, 2));
