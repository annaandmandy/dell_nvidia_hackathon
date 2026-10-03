---
name: mergeops-identity
description: Identify deal team members (HarborStone buyer / QuantaShield target) from their Slack user ID or name using the roles.json registry. Use for "who am I", "who is <name>", "what company is X from", "can X approve".
metadata: {"openclaw": {"requires": {"bins": ["node"]}}}
---

# Meridian Identity

The identity registry is `{baseDir}/roles.json` (a copy of `data/roles.json`).
Never guess identities — always run the lookup script and answer from its output.

## Who am I / who sent this message

Take the sender's Slack user ID (looks like `U0C675Y48CR`) from the inbound
message metadata, then run:

```bash
node {baseDir}/identify.mjs id <SLACK_USER_ID>
```

## Who is <someone>

Look up by partial name (case-insensitive) or Slack ID:

```bash
node {baseDir}/identify.mjs find <name-or-slack-id>
```

## List everyone

```bash
node {baseDir}/identify.mjs list
```

## Answer format

The script prints JSON. If `known` is true, reply like:

> :large_blue_circle: *Anna Huang* — HarborStone CFO (HarborStone Financial Group). Can approve: yes

Use the `company_emoji` from the output. If `known` is false, say the Slack ID is
not registered and ask the integration lead to add it to `data/roles.json`.
