# AGENTS.md - Project Context and Guidelines for AI Assistants

Hey there, fellow agent. Welcome to this project. This document serves as your single source of truth for understanding the project's nature, the stack, and how the user expects us to work.

## Project Essence
This is a **self-hosted infrastructure stack** meticulously crafted for high-availability, security, and deep monitoring. It's not just a collection of Docker containers; it's a robust bastion designed to manage multiple domains, provide secure routing, and actively block threats.

## The Tech Stack
*   **Edge Router:** Traefik (the brain of the operation).
*   **Security:** CrowdSec (multi-layered protection with LAPI/Bouncers) + Redis (caching).
*   **Observability:** Grafana, Loki, and Alloy (the telemetry pipeline).
*   **Automation:** Python scripts for configuration generation and certificate management.
*   **Custom Tooling:** Anubis for bot management and mitigation (Proof of Work challenges) and a Telegram Bot for real-time alerts.
*   **Orchestration:** Docker Compose with a modular structure.

## How we Roll (User Preferences)
The user is a pro who cares about **solidity** over speed. Here’s how you should behave:

1.  **Be Concise & Colloquial:** No corporate fluff. Speak clearly, get to the point, and don't be afraid to use a natural, relaxed tone if appropriate.
2.  **Solidity First:** Every change must prioritize security, performance, and robustness. If a solution is "quick but dirty," it's probably wrong.
3.  **No Hallucinations:** Don't guess. If you're unsure about a Traefik middleware or a CrowdSec scenario, look it up in the official documentation. Facts over magic.
4.  **Executive Summaries:** When explaining or proposing changes, start with a high-level "why" and "what" before diving into the "how."
5.  **Robustness over Everything:** The goal is a production-grade environment. Edge cases matter. Errors should be handled gracefully.

## Pro-tips for Agents
*   Check the `Makefile` and `scripts/` directory before reinventing the wheel. There's already a lot of automation here.
*   Respect the modular Docker Compose structure. Don't dump everything into one file.
*   Security is always on the menu. If you see a way to harden a configuration, mention it.

Happy coding! Let's keep this stack bulletproof.
