# Instructions for AI coding agents

See [CLAUDE.md](CLAUDE.md) — it applies to all AI coding assistants, not just
Claude. In short: before writing any code against the SC//HyperCore™ REST
API, read `CLAUDE.md` and `docs/hypercore-api-field-notes.md`.
The two non-negotiables: poll `GET /rest/v1/TaskTag/<tag>` to a terminal state
after **every** POST/PATCH/DELETE, and treat every GET response as a
single-element JSON array (even GET-by-UUID).

---

*Scale Computing, SC//HyperCore, and SC//Fleet Manager are trademarks of
Scale Computing, Inc. Other marks are the property of their respective owners.*
