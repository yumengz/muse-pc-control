# Muse PC Control project instructions

- Target macOS and Python 3.11+.
- Preserve localhost-only binding by default.
- Every `/api/*` endpoint must require bearer-token authentication.
- Never hardcode, print, log, or commit access tokens.
- Command execution must use exact entries from `allowed.txt`; never permit prefix, substring, glob, or user-supplied executable matching.
- Keep command timeout and output limits enforced.
- Validate mouse buttons, keys, text length, coordinates, and request sizes.
- Never add direct port-forwarding instructions; recommend authenticated Cloudflare Tunnel, Tailscale, or ngrok over HTTPS.
- Keep macOS Screen Recording and Accessibility permission guidance current.
- Mock desktop automation and screenshots in tests; tests must not control the real machine.
