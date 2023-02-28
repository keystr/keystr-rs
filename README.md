# **Keystr**: Nostr Keystore

An application for managing Nostr keys.
Written in Rust, with simple UI (Iced).

## Features

- Key management:
  - Import of keys
  - Save/Load keys
- Delegations: Create NIP-26 delegation

## Screenshot

<img src="media/screenshot-01-deleg.png" align="center" title="screenshot delegation" border="1">

## Roadmap

- Safekeeping of keys
- Delegation (NIP-26)
- Profile
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

- Protocol definition  https://github.com/nostr-protocol/nostr  protocol

- Nostr projects  https://github.com/aljazceru/awesome-nostr

- NIP-26 Delegations  https://github.com/nostr-protocol/nips/blob/master/26.md

- Rust-nostr lib  https://github.com/rust-nostr/nostr

- NostrTool, key generation and delegation playground  https://github.com/kdmukai/nostrtool
