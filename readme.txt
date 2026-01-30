=== BCM Protection ===
Contributors: bcmnetwork
Tags: anti-spam, comments, registration, bot
Requires at least: 6.0
Requires PHP: 7.4
Stable tag: 0.2.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight anti-bot/spam protection for comments and user registrations.

== Description ==
BCM Protection adds a hidden honeypot field, a timestamp, and a nonce to comment and registration forms.
Bots and spam scripts typically fail these checks.

== Features ==
- Blocks comment spam (before insert)
- Blocks registration spam (shows error on form)
- No external services, no API keys

== Notes ==
If you use a custom form that does not output WordPress hooks for fields/nonces, the protection may not apply.
