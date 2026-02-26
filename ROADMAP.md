# Roadmap

## Userstyles

Per-domain custom CSS injection. Users write CSS in the portal that the proxy injects into matching pages via `<style>` tags. Subdomain-aware domain matching. Supports create, edit, toggle, and delete. Natural extension of the existing element hiding CSS pipeline.

## Userscripts

Per-domain custom JavaScript injection, similar to Greasemonkey/Tampermonkey. Users write JS in the portal that the proxy injects into matching pages via `<script>` tags. Requires metadata block parsing (`@match`, `@run-at`, `@require`), CSP header handling, and careful security review since injected JS has full DOM access.

## Admin Role

Add `is_admin` column to `credentials` table. First registered user becomes admin. Admins can manage rules, subscriptions, userstyles, and userscripts for other users via the portal. Enables use cases like parental controls, shared-network policy enforcement, and setting up rules for less technical users.
