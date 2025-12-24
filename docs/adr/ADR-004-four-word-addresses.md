# ADR-004: Four-Word Human-Readable Addresses

## Status

Accepted

## Context

P2P networks traditionally use opaque identifiers for addressing:

- **IP addresses**: `192.168.1.100:9000` - Hard to remember, expose network topology
- **Hex hashes**: `0x7a3f8b...` - Completely unmemorable
- **Base58 IDs**: `QmYwAPJz...` - Slightly better but still opaque

These create usability challenges:
- Users cannot remember or share addresses verbally
- Typos are common and hard to detect
- No semantic meaning to aid recall
- Phishing attacks exploit similar-looking addresses

We needed an addressing scheme that is:
1. Human-readable and memorable
2. Verbally communicable (phone, video calls)
3. Typo-resistant
4. Compact enough for practical use

## Decision

We adopt **four-word addresses** using the `four-word-networking` crate to encode network addresses into sequences of four English words.

### Encoding Scheme

```
IPv4:Port → 4 Words
192.168.1.100:9000 → "welfare-absurd-king-ridge"
```

The encoding uses:
- **2,048-word dictionary** (BIP-39 compatible)
- **Adaptive encoding** for different address types
- **Checksum integration** for error detection
- **Hyphen or space separators** for clarity

### Architecture Integration

```
┌─────────────────────────────────────────────────────────────────┐
│                      User Interface                              │
│    "Connect to welfare-absurd-king-ridge"                       │
└─────────────────────────────────────────┬───────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   FourWordAddress Type                           │
│    ┌─────────────────────────────────────────────────────────┐  │
│    │  parse("welfare-absurd-king-ridge")                      │  │
│    │  → FourWordAddress { words: ["welfare","absurd",         │  │
│    │                              "king","ridge"] }            │  │
│    └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────┬───────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   WordEncoder (four-word-networking)             │
│    ┌─────────────────────────────────────────────────────────┐  │
│    │  decode_to_socket_addr()                                 │  │
│    │  → SocketAddr(192.168.1.100:9000)                       │  │
│    └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────┬───────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Transport Layer (ant-quic)                     │
│    connect(192.168.1.100:9000)                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation

```rust
// src/bootstrap/mod.rs
use four_word_networking::FourWordAdaptiveEncoder;

pub struct FourWordAddress(pub String);

impl FourWordAddress {
    pub fn from_string(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(['.', '-']).collect();
        if parts.len() != 4 {
            return Err(P2PError::Bootstrap(BootstrapError::InvalidData(
                "Four-word address must have exactly 4 words".into(),
            )));
        }
        Ok(FourWordAddress(parts.join("-")))
    }
}

pub struct WordEncoder;

impl WordEncoder {
    pub fn encode_socket_addr(&self, addr: &SocketAddr) -> Result<FourWordAddress> {
        let encoder = FourWordAdaptiveEncoder::new()?;
        let encoded = encoder.encode(&addr.to_string())?;
        Ok(FourWordAddress(encoded.replace(' ', "-")))
    }

    pub fn decode_to_socket_addr(&self, words: &FourWordAddress) -> Result<SocketAddr> {
        let encoder = FourWordAdaptiveEncoder::new()?;
        let normalized = words.0.replace(' ', "-");
        let decoded = encoder.decode(&normalized)?;
        decoded.parse::<SocketAddr>()
    }
}
```

### Identity Integration

Four-word addresses integrate with the identity system:

```rust
// User registration with four-word identity
let words = ["welfare", "absurd", "king", "ridge"];
let keypair = MlDsaKeyPair::generate()?;
let handle = register_identity(words, &keypair).await?;

// The four words become the user's memorable identifier
// Can be shared verbally: "My address is welfare-absurd-king-ridge"
```

### Separator Flexibility

Both formats are accepted and normalized:
- Hyphenated: `welfare-absurd-king-ridge`
- Spaced: `welfare absurd king ridge`
- Mixed: `welfare.absurd-king ridge`

All normalize to hyphenated form internally.

### Entropy and Security

With a 2,048-word dictionary (2^11 words), four words provide:
- **44 bits of entropy** (2^44 ≈ 17.6 trillion combinations)
- Sufficient for IPv4 + port encoding
- Not intended for cryptographic key material

For cryptographic identities, the four words reference a full ML-DSA-65 public key stored in the DHT.

## Consequences

### Positive

1. **Memorability**: Users can remember their addresses
2. **Verbal communication**: Easy to share over phone/video
3. **Typo detection**: Invalid words are caught immediately
4. **User-friendly**: Natural language feels approachable
5. **Privacy**: Doesn't expose raw IP addresses in casual sharing

### Negative

1. **Length**: 4 words + separators longer than raw IP
2. **Dictionary dependency**: Must ship word list with application
3. **Localization**: English-centric (though can be translated)
4. **Collision potential**: 44 bits may conflict at massive scale

### Neutral

1. **Learning curve**: Users must understand the concept initially
2. **Mixed usage**: Some contexts still use raw addresses internally

## Alternatives Considered

### Three-Word Addresses

Shorter but less entropy:
- 33 bits = 8.6 billion combinations
- Higher collision risk
- Less distinctive

**Rejected**: Insufficient entropy for global network.

### Five-Word Addresses

More entropy but less memorable:
- 55 bits = very large space
- Harder to remember
- Longer to communicate

**Rejected**: Diminishing usability returns.

### Hex with Checksum (like Ethereum)

`0x7a3F8b9C...` with EIP-55 checksum.

**Rejected because**:
- Not human-readable
- Cannot be communicated verbally
- Technical appearance alienates users

### QR Codes Only

Require QR scanning for all sharing.

**Rejected because**:
- Cannot work in voice communication
- Requires camera access
- Not universally accessible

### DNS-Like Names

`alice.saorsa.network`

**Rejected because**:
- Requires centralized registry
- Name squatting issues
- Conflicts with P2P philosophy

## Word List Selection

The word list is based on BIP-39 with modifications:
- 2,048 words
- 4-8 characters preferred
- No homophones (write/right)
- No profanity
- No offensive terms
- Phonetically distinct

Example words: `abandon`, `ability`, `able`, `about`, `above`, `absent`, `absorb`, `abstract`...

## References

- [four-word-networking Crate](https://crates.io/crates/four-word-networking)
- [BIP-39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [What3Words](https://what3words.com/) - Similar concept for geographic locations
- [Diceware](https://diceware.com/) - Word-based passphrase generation
- [RFC 1751: Human-Readable 128-bit Keys](https://www.rfc-editor.org/rfc/rfc1751)
