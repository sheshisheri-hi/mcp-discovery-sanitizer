# LinkedIn assets

Quick links for posting:

- **Flashy HTML (public):** https://cdn.jsdelivr.net/gh/sheshisheri-hi/mcp-discovery-sanitizer-deck@main/index.html
- **Same file in private repo:** [`docs/one-pager.html`](one-pager.html)
- **Original notes:** [`docs/LINKEDIN-NOTES.md`](LINKEDIN-NOTES.md)

---

# LinkedIn post (copy-paste ready)

Use this as a single post, or split the **Carousel** section into slides.

---

## Post

One poisoned MCP server.

Every teammate’s agent.

That’s not a jailbreak pasted into chat.
That’s discovery metadata — `instructions` + `tools/list` — folded straight into the system prompt.

And if the server marks it `cacheScope: public`?
Your shared gateway can serve that poison to everyone behind it.

I built a tiny fix: a CPU-only discovery sanitizer.

No LLM.
No GPU.
Just a gate that says allow / strip / block *before* the agent trusts the blob.

What it does:
→ Bounds and trips on hostile `instructions`
→ Refuses public cache from untrusted servers
→ Treats tool text as untrusted
→ SHA-256 hashes the blob so swaps show up in a diff

Before: server → public cache → everyone’s prompt
After: server → sanitizer → allow / strip / block

Weekend sample. Private repo. 48 tests green.

If you run MCP at work and you’re not sanitizing discovery, you’re trusting whoever registered the server.

#AISecurity #MCP #AgentSecurity #LLMOps

---

## Carousel (6 slides — paste one slide per card)

**Slide 1 — Hook**
One poisoned MCP server.
Every teammate’s agent.

**Slide 2 — The twist**
Agents don’t just “read tools.”
They paste server `instructions` into the system prompt.

Nobody asked if that text was safe.

**Slide 3 — The amplifier**
MCP lets a server say: cache this for everyone (`cacheScope: public`).

One bad list.
Company-wide injection.

**Slide 4 — The fix**
A discovery sanitizer in front of the agent.

Allow.
Strip.
Block.

With reasons you can actually read.

**Slide 5 — What it checks**
• Bound / tripwire on `instructions`
• No public cache from strangers
• Tool descriptions = untrusted
• Hash the blob for audit diffs

CPU only. No model required.

**Slide 6 — CTA**
Stop folding raw discovery into the system prompt.

Gate it first.

(Private sample: mcp-discovery-sanitizer)

---

## Comment you can pin under the post

Built as a weekend Stage-discovery gate (MCP-2026-008 / 015 style risk).
Not a full WAF. Not MCP-Guard Stage I. Just the missing filter before `initialize` / `tools/list` hit the prompt.

Happy to walk through the verdict JSON if useful.
