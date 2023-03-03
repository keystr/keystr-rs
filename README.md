# **Keystr**: Nostr Keystore

An application for managing Nostr keys.
Written in Rust, with simple UI (Iced).

## Features

- Safekeeping of keys:
  - Import of keys (secret or public)
  - Save/Load keys (encrypted with password)
- Delegations: Create NIP-26 delegation

## Screenshot

<img src="media/screenshot-01-deleg.png" align="center" title="screenshot delegation" border="1">

## Roadmap

- Profile metadata
- Remote Signer (NIP-46)

## Building and Running

- Prerequisite: `rust`, v >= 1.67

- Simply run:  `cargo run`

### Running Tests

- `cargo tests`

## Contributing

Create an issue, PR, or discussion.

## License: MIT

## References

- NIP-26 Delegations Spec https://github.com/nostr-protocol/nips/blob/master/26.md
- NIP-26 Delegations Status  https://hackmd.io/fskWGX_XRxG45fMrub8OiA?view
- Rust-nostr lib  https://github.com/rust-nostr/nostr
- NostrTool, key generation and delegation playground  https://github.com/kdmukai/nostrtool
- Nostr Protocol definition  https://github.com/nostr-protocol/nostr  protocol
- Nostr projects  https://github.com/aljazceru/awesome-nostr

## Contact

Nostr: optout@nostrplebs.com npub1kxgpwh80gp79j0chc925srk6rghw0akggduwau8fwdflslh9jvqqd3lecx
