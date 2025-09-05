# Saorsa Core Agents API (AGENTS_API.md)

Copyright (C) 2024 Saorsa Labs Limited — Licensed under AGPL-3.0-or-later.

This document is written for LLM agents and autonomous clients to interact with Saorsa Core. It describes the stable agent-facing API surface, object models, addressing, and example flows for building large-scale peer-to-peer applications with identity, storage, messaging, real-time media, and groups.

Status: evolving, backwards-compatible where possible. All production calls are panic-free and authenticated by design. Examples use Rust-style signatures and JSON payloads, but the protocol is language-agnostic.

## Table of Contents

### Core Concepts
- [Principles](#principles)
- [Addressing and Keys](#addressing-and-keys)
- [Object Model](#object-model-core-records)
- [Quick Start for Agents](#quick-start-for-agents)

### API Reference
- [Identity API](#identity-api) - Claim identities, manage endpoints and devices
- [Group API](#group-api) - Create and manage groups with membership
- [DHT API](#dht-api) - Authenticated distributed storage operations
- [Virtual Disk API](#virtual-disk-api) - File systems and website publishing
- [Messaging API](#messaging-api-high-level-service) - Secure messaging and content
- [Real-Time Media API](#real-time-media-api) - Audio/video calls and screen sharing
- [Routing & Trust API](#routing--trust-api) - EigenTrust and peer selection
- [Transport API](#transport-api-quic) - Low-level QUIC connections
- [Storage Control API](#storage-control-api) - Placement and repair
- [Friend Mesh Backup API](#friend-mesh-backup-api) - Cooperative backup

### Application Development
- [Agent Decision Trees](#agent-decision-trees) - Choose the right APIs
- [Common Patterns](#common-patterns) - Best practices and examples
- [Example: Building "Communitas"](#example-building-communitas) - Complete app example
- [Security and Anti-Phishing](#anti-phishing-and-name-safety)
- [Error Handling](#error-handling-and-telemetry)

### Reference
- [Quick Reference](#quick-reference-calls) - All API calls at a glance
- [Implementation Notes](#implementation-notes-for-agents)
- [Compatibility](#compatibility-and-versioning)


## Principles

- Trust-minimized: Identities, groups, and data are addressed by four-word identifiers hashed to 32-byte keys.
- Zero-panic production: No `unwrap`/`expect`/`panic!` in production code. Errors are explicit and typed.
- End-to-end encryption: ML-DSA for identity auth; MLS and PQC symmetric crypto for content.
- Two-tier storage: DHT distribution with FEC-sealed containers; optional local member disks and friend-mesh repair.
- Human-verifiable addressing: Four-word addressing prevents lookalike/phishing through a constrained dictionary and checksum.
- Structured telemetry and tracing: All subsystems emit structured events for observability.


## Quick Start for Agents

### Essential API Flow for P2P Applications

**Step 1: Initialize Identity**
```rust
// 1. Generate keypair and claim four-word identity
let words = ["river", "spark", "honest", "lion"];
let (pk, sk) = mldsa_generate();
let sig = mldsa_sign(&sk, words.join("-"));
identity_claim(words.clone(), PubKey::new(pk), Sig::new(sig)).await?;
```

**Step 2: Setup Connectivity**  
```rust
// 2. Publish endpoints and device forwards
identity_publish_endpoints_signed(id_key, endpoints, ep_sig).await?;
device_publish_forward_signed(id_key, forward, sig).await?;
```

**Step 3: Enable Messaging**
```rust
// 3. Initialize messaging service
let messaging = MessagingService::new(four_word_address, dht_client).await?;
```

### Common Application Patterns

- **1:1 Chat App**: Identity API + Messaging API + Transport API
- **Group Collaboration**: + Group API + Virtual Disk API + Real-Time Media API  
- **Public Website**: + Virtual Disk API (website publishing)
- **Secure File Sharing**: + Storage Control API + Friend Mesh Backup API
- **Video Conferencing**: + Real-Time Media API + Group API

### Agent Decision Matrix

| Use Case | Primary APIs | Secondary APIs |
|----------|--------------|----------------|
| User onboarding | Identity | Transport, DHT |
| Send message | Messaging | DHT, Transport |  
| Group chat | Group, Messaging | Real-Time Media |
| File sharing | Virtual Disk, Storage Control | Friend Mesh Backup |
| Video call | Real-Time Media, Messaging | Group, Transport |
| Website publishing | Virtual Disk, DHT | Identity |

## Addressing and Keys

- Four-Word Address: `[Word; 4]` (e.g., "river-spark-honest-lion"). Validated by the Four Word Networking (FWN) dictionary and encoding rules.
- Identity Key (`Key`): `blake3(utf8(join(words,'-')))` → 32 bytes.
- Context Keys: `compute_key(context: &str, content: &[u8])` → 32 bytes. Used for derived records such as device sets, manifests, websites, and virtual disks.
- Network Endpoints: Public IP endpoints can be represented as four-word strings for display (FW4/FW6 encodings).


## Object Model (Core Records)

- IdentityPacketV1
  - `v: u8`
  - `words: [String; 4]` — user-chosen four words
  - `id: Key` — blake3(utf8(words))
  - `pk: Vec<u8>` — ML-DSA public key
  - `sig: Vec<u8>` — ML-DSA signature over `utf8(words)`
  - `endpoints: Vec<NetworkEndpoint>` — optional public reachability
  - `ep_sig: Option<Vec<u8>>` — signature over `(id || pk || CBOR(endpoints))`
  - `website_root: Option<Key>` — public website root object key (see Website Disk)
  - `device_set_root: Key` — device forwards CRDT root (derived)

- DeviceSetV1
  - OR-Set of `Forward { proto, addr, meta }` entries for the identity’s devices and forwards

- GroupIdentityPacketV1
  - `v: u8`, `words: [String;4]`, `id: Key` — group identifier
  - `group_pk: Vec<u8>`, `group_sig: Vec<u8>` — ML-DSA of the group
  - `members: Vec<MemberRef { member_id: Key, member_pk: Vec<u8> }>`
  - `membership_root: Key` — Merkle root of sorted member IDs
  - `created_at: u64`, `mls_ciphersuite: Option<u16>`

- GroupPacketV1
  - Current group epoch state and container bindings: `membership`, `forwards_root`, `container_root`

- GroupForwardsV1
  - `endpoints: Vec<GroupEndpoint { member_pub, forward, ts }>` per member

- ContainerManifestV1
  - `object: Key`, `fec: { k, m, shard_size }`, `assets: Vec<Key>`, `sealed_meta: Option<Key>`
  - Represents a sealed container (object root) with FEC parameters and asset references


## Identity API

Purpose: Claim and fetch identities, publish reachability and device forwards, and subscribe to changes.

- identity_claim(words: [Word; 4], pubkey: PubKey, sig: Sig) -> Result<()>
  - Validates words (FWN), verifies ML-DSA signature over `utf8(words)` with `pubkey`, computes `id` and `device_set_root`, then stores IdentityPacketV1 under `id` in the DHT with quorum policy.
  - Errors: invalid words, invalid pubkey/sig, DHT policy violations.

- identity_fetch(key: Key) -> Result<IdentityPacketV1>
  - Fetches identity packet by `id` key from the DHT.

- identity_publish_endpoints_signed(id_key: Key, endpoints: Vec<NetworkEndpoint>, ep_sig: Sig) -> Result<()>
  - Verifies `ep_sig` over `(id || pk || CBOR(endpoints))` using the stored identity `pk` and updates the packet.
  - Auto-computes FW4/FW6 display forms when possible.

- device_publish_forward(id_key: Key, fwd: Forward) -> Result<()>
  - Adds or updates a forward in `DeviceSetV1` under `device_set_root`. Uses delegated write auth; emits events.

- device_publish_forward_signed(id_key: Key, fwd: Forward, sig: Sig) -> Result<()>
  - Same as above with explicit signature material for authorization contexts that require proof on canonical content.

- device_subscribe(id_key: Key) -> Subscription<Forward>
  - Subscribes to forward updates for an identity.

- identity_set_website_root(id_key: Key, website_root: Key, sig: Sig) -> Result<()>
  - Updates an identity's website root with signature verification.
  - Canonical signing: Message bytes: `b"saorsa-identity:website_root:v1" || id || pk || CBOR(website_root)`
  - Verifies `sig` matches canonical message using stored identity `pk`, then updates IdentityPacketV1.

- group_identity_canonical_sign_bytes(id: &Key, membership_root: &Key) -> Vec<u8>
  - Returns canonical bytes for group identity signing: `b"saorsa-group:identity:v1" || id || membership_root`
  - Used for consistent signature verification across group operations.

Notes
- `WriteAuth` enforces signatures at `dht_put` time. For identity and group canonical records, signatures are verified against canonical bytes to prevent malleability.
- `NetworkEndpoint { ipv4, ipv6, fw4, fw6 }` supports both raw and four-word display addressing.


## Group API

Purpose: Create and publish group identities, maintain group state, endpoints, and storage containers.

- group_identity_create(words: [Word; 4], members: Vec<MemberRef>) -> Result<(GroupIdentityPacketV1, GroupKeyPair)>
  - Derives `id` from words, computes `membership_root` from sorted `member_id`s, generates ML-DSA group keypair, signs canonical message `(id || membership_root)`.

- group_identity_publish(packet: GroupIdentityPacketV1) -> Result<()>
  - Validates words/id and signature; stores canonical packet at `id` key.

- group_identity_fetch(id_key: Key) -> Result<GroupIdentityPacketV1>
  - Reads group identity by id key.

- group_forwards_put(fwd: &GroupForwardsV1, group_id: &[u8], policy: &PutPolicy) -> Result<PutReceipt>
  - Stores under `blake3("group-fwd" || group_id)`; used for up-to-date group forwarding meta.

- group_forwards_fetch(group_id: &[u8]) -> Result<GroupForwardsV1>

- group_put(pkt: &GroupPacketV1, policy: &PutPolicy) -> Result<PutReceipt>
  - Stores current group epoch/control record under `blake3("group" || group_id)`.

- group_fetch(group_id: &[u8]) -> Result<GroupPacketV1>

- group_identity_update_members_signed(id_key: Key, new_members: Vec<MemberRef>, group_pk: Vec<u8>, group_sig: Sig) -> Result<()>
  - Updates group membership with signature verification.
  - Canonical signing: Message bytes: `group_identity_canonical_sign_bytes(id, new_root)`
  - Verifies `group_sig` with `group_pk`, replaces members, recomputes `membership_root`, stores updated packet.

- group_member_add(id_key: Key, member: MemberRef, group_pk: Vec<u8>, group_sig: Sig) -> Result<()>
  - Convenience function to add a member to existing group.
  - Internally fetches current packet, adds member, calls `group_identity_update_members_signed`.

- group_member_remove(id_key: Key, member_id: Key, group_pk: Vec<u8>, group_sig: Sig) -> Result<()>
  - Convenience function to remove a member from existing group.
  - Internally fetches current packet, removes member, calls `group_identity_update_members_signed`.

- group_epoch_bump(id_key: Key, proof: Option<Vec<u8>>, group_pk: Vec<u8>, group_sig: Sig) -> Result<()>
  - Increments group epoch with signature verification.
  - Canonical signing: Message bytes: `b"saorsa-group:epoch:v1" || id || epoch`
  - Verifies `group_sig` with `group_pk`, increments epoch, stores updated GroupPacketV1.

Conventions
- Group storage containers are referenced via `GroupPacketV1.container_root` and described by `ContainerManifestV1`.
- For MLS, `mls_ciphersuite` and `proof` fields are carried as opaque bytes for verification by MLS-capable clients.


## DHT API

Purpose: Authenticated, policy-driven reads/writes to the Trust-Weighted Kademlia (TwDHT).

- dht_put(key: Key, bytes: Bytes, policy: &PutPolicy) -> Result<PutReceipt>
  - `PutPolicy { quorum: usize, ttl: Option<Duration>, auth: Box<dyn WriteAuth> }`
  - Performs record-type aware verification (Identity/Group canonical checks, DeviceSet CRDT semantics, etc.), publishes change events, and records telemetry.
  - PutReceipt: `{ key, timestamp, storing_nodes: Vec<Vec<u8>> }`.

- dht_get(key: Key, quorum: usize) -> Result<Bytes>
  - Fetches with quorum and records telemetry.

- dht_watch(key: Key) -> Subscription<Bytes>
  - Event stream of updates for a DHT key.

- set_dht_instance(dht: Arc<TwDht>) -> bool
  - Installs a process-global DHT for the API.

Security
- Identity and Group records enforce word validity, id/key matching, and ML-DSA signature verification on canonical bytes.
- Endpoint updates require explicit `ep_sig` independent from base identity `sig`.


## Routing & Trust API

- record_interaction(peer: Vec<u8>, outcome: Outcome) -> Result<()>
  - Updates EigenTrust with interaction outcome and records telemetry.
  - `Outcome = { Ok, Timeout, BadData, Refused }`.

- eigen_trust_epoch() -> Result<()>
  - Triggers a maintenance tick; used for scheduling trust recomputations.

- route_next_hop(target: Vec<u8>) -> Option<Contact>
  - Returns a trust-weighted best next-hop `Contact { node_id, endpoint }` for target routing (simplified selection combining XOR-distance and trust).


## Transport API (QUIC)

Provides low-level primitives for direct connections and typed streams. WebRTC bridging is available via messaging modules for real-time A/V.

- quic_connect(ep: &Endpoint { address: String }) -> Result<Conn { peer: Vec<u8> }>
  - Creates/initializes a P2P node if needed and connects to `address`.

- quic_open(conn: &Conn, class: StreamClass) -> Result<Stream { id: u64, class: StreamClass }>
  - `StreamClass = { Control, Mls, File, Media }` (telemetry-tagged).

Media Notes
- Real-time audio/video/screen-share flows are supported via WebRTC over QUIC with signaling handled by the messaging/webrtc bridge. Agents generally don't open raw media streams; they invoke call flows in the Messaging API (see below) which use these transport primitives under the hood.


## Real-Time Media API

Provides high-level audio/video calling with WebRTC-over-QUIC transport, supporting 1:1 and group calls with screen sharing.

### Call Management

- call_initiate(recipient: FourWordAddress, media_config: MediaConfig) -> Result<CallHandle>
  - Initiates call with specified recipient  
  - `MediaConfig { audio: bool, video: bool, screen_share: bool, quality: QualityProfile }`
  - Returns handle for call control operations

- call_answer(call_id: CallId, media_config: MediaConfig) -> Result<CallHandle>
  - Accepts incoming call with specified media capabilities

- call_reject(call_id: CallId, reason: RejectReason) -> Result<()>
  - Rejects incoming call with reason code
  - `RejectReason = { Busy, Declined, Unavailable, UnsupportedMedia }`

- call_hangup(handle: CallHandle) -> Result<CallSummary>
  - Ends active call and returns summary statistics
  - `CallSummary { duration, quality_metrics, participant_count, bytes_transferred }`

### Group Calls

- group_call_create(group_id: Key, media_config: MediaConfig) -> Result<GroupCallHandle>
  - Creates group call session within existing group
  - Automatically invites all group members

- group_call_join(call_id: GroupCallId, media_config: MediaConfig) -> Result<GroupCallHandle>
  - Joins existing group call session

- group_call_invite(handle: GroupCallHandle, participants: Vec<FourWordAddress>) -> Result<Vec<InviteStatus>>
  - Invites additional participants to group call
  - Returns per-participant invitation status

- group_call_remove(handle: GroupCallHandle, participant: FourWordAddress) -> Result<()>
  - Removes participant from group call (admin operation)

### Media Control

- media_toggle_audio(handle: CallHandle, enabled: bool) -> Result<()>
  - Mutes/unmutes audio during active call

- media_toggle_video(handle: CallHandle, enabled: bool) -> Result<()>
  - Enables/disables video during active call  

- media_toggle_screen_share(handle: CallHandle, enabled: bool) -> Result<()>
  - Starts/stops screen sharing

- media_set_audio_device(handle: CallHandle, device_id: AudioDeviceId) -> Result<()>
  - Switches audio input/output device

- media_set_video_device(handle: CallHandle, device_id: VideoDeviceId) -> Result<()>
  - Switches camera device

- media_adjust_quality(handle: CallHandle, quality: QualityProfile) -> Result<()>
  - Dynamically adjusts media quality based on network conditions
  - `QualityProfile = { Low, Medium, High, Auto }`

### Call Events and Monitoring

- call_subscribe_events(handle: CallHandle) -> Subscription<CallEvent>
  - Subscribe to call state changes and events
  - `CallEvent = { ParticipantJoined, ParticipantLeft, MediaToggled, QualityChanged, NetworkEvent }`

- call_get_stats(handle: CallHandle) -> Result<CallStats>
  - Retrieves real-time call quality statistics
  - `CallStats { latency, packet_loss, bitrate, jitter, participants: Vec<ParticipantStats> }`

- call_record(handle: CallHandle, config: RecordingConfig) -> Result<RecordingHandle>
  - Starts call recording (requires participant consent)
  - `RecordingConfig { audio_only: bool, include_screen: bool, storage_location: StorageTarget }`

### Advanced Features

- call_create_breakout(handle: GroupCallHandle, participants: Vec<FourWordAddress>) -> Result<GroupCallHandle>
  - Creates breakout room with subset of participants

- call_enable_noise_cancellation(handle: CallHandle, enabled: bool) -> Result<()>
  - Toggles AI-powered noise cancellation

- call_set_background(handle: CallHandle, background: BackgroundEffect) -> Result<()>
  - Sets virtual background or blur effect
  - `BackgroundEffect = { None, Blur, Image(data), Video(data) }`


## Virtual Disk API

Every entity (individual, group, organization, channel) can have two virtual disks: private (encrypted) and public (website). This API provides file system operations over the DHT with FEC protection.

### Core Virtual Disk Operations

- disk_create(entity_id: Key, disk_type: DiskType, config: DiskConfig) -> Result<DiskHandle>
  - `DiskType = { Private, Website }`
  - `DiskConfig { fec_params: FecParams, encryption: EncryptionConfig, cache_policy: CachePolicy }`
  - Creates virtual disk root and initializes metadata

- disk_mount(entity_id: Key, disk_type: DiskType) -> Result<DiskHandle>
  - Mounts existing virtual disk for operations

- disk_write(handle: DiskHandle, path: &str, content: &[u8], metadata: FileMetadata) -> Result<WriteReceipt>
  - Writes file to path with automatic FEC sealing and DHT distribution
  - `FileMetadata { mime_type, permissions, created_at, tags }`

- disk_read(handle: DiskHandle, path: &str) -> Result<Vec<u8>>
  - Reads file, reconstructing from FEC shards if needed

- disk_list(handle: DiskHandle, path: &str, recursive: bool) -> Result<Vec<FileEntry>>
  - Lists directory contents with metadata
  - `FileEntry { path, size, modified_at, file_type, permissions }`

- disk_delete(handle: DiskHandle, path: &str) -> Result<()>
  - Marks file as deleted and schedules shard cleanup

- disk_sync(handle: DiskHandle) -> Result<SyncStatus>
  - Forces synchronization of pending changes to DHT
  - Returns `SyncStatus { pending_writes, conflicts, last_sync }`

### Website Publishing Operations

- website_set_home(handle: DiskHandle, markdown_content: &str, assets: Vec<Asset>) -> Result<()>
  - Sets `home.md` as website entry point with linked assets
  - `Asset { path, content, mime_type }` for images, CSS, etc.

- website_publish(entity_id: Key, website_root: Key) -> Result<PublishReceipt>
  - Updates entity's IdentityPacket with new website_root
  - Makes website publicly accessible via four-word address

- website_get_manifest(website_root: Key) -> Result<WebsiteManifest>
  - Retrieves website structure and asset references
  - `WebsiteManifest { home_md_key, assets: Vec<AssetRef>, navigation, metadata }`

### Collaborative Operations

- disk_share(handle: DiskHandle, path: &str, permissions: Permissions, members: Vec<Key>) -> Result<ShareToken>
  - Shares file/directory with specific members
  - `Permissions { read, write, admin }` with role-based access

- disk_collaborate(handle: DiskHandle, path: &str, session_id: SessionId) -> Result<CollabSession>
  - Initiates real-time collaborative editing session
  - Returns conflict-free replicated data type (CRDT) session

- disk_resolve_conflict(handle: DiskHandle, conflict: FileConflict, resolution: ConflictResolution) -> Result<()>
  - Resolves file conflicts using specified strategy
  - `ConflictResolution = { TakeLocal, TakeRemote, Merge(strategy), Manual(content) }`

### Advanced Operations

- disk_snapshot(handle: DiskHandle, name: &str) -> Result<SnapshotId>
  - Creates immutable snapshot of current disk state

- disk_restore(handle: DiskHandle, snapshot_id: SnapshotId) -> Result<()>
  - Restores disk to previous snapshot state

- disk_encrypt_for_group(handle: DiskHandle, group_id: Key, mls_key: &[u8]) -> Result<()>
  - Re-encrypts disk content for group access using MLS derived keys

## Virtual Disks and Websites

Every entity (individual, group, organization, channel) can expose two logical disks:

1) Private Disk (entity-scoped, group-encrypted)
   - Root Key: `disk_root = compute_key("disk", entity_id.as_bytes())`
   - Organization: content addressed by path → object key mapping using `ContainerManifestV1` for each root object.
   - Encryption: MLS or group ML-DSA derived symmetric keys; objects are sealed and sharded with FEC `(k,m,shard_size)` across DHT, with optional member-local caches.
   - Access: membership governed; members reconstruct via DHT + local caches.

2) Website Disk (public)
   - Root Key: `website_root` in `IdentityPacketV1` or `compute_key("website", entity_id.as_bytes())` if not set.
   - Convention: `home.md` is the entry file (Markdown-only web). Assets referenced by relative paths resolve to `assets/` keyed objects in the same container or sibling keys.
   - Publishing: write manifests and assets to DHT under context keys, set/refresh `website_root` on identity.
   - Browsing: agents fetch `IdentityPacketV1`, read `website_root`, fetch `ContainerManifestV1` at root, then fetch `home.md` and linked assets.

Addressing Examples
- Individual disk: `disk_root = blake3("disk" || ID)` where `ID = blake3(words)`.
- Group disk: same construction with the group's `id` from `GroupIdentityPacketV1`.
- Channel disk: derive channel key: `channel_id = compute_key("channel", group_id.as_bytes())` then `disk_root = compute_key("disk", channel_id.as_bytes())`.


## Storage Control API

High-level placement and maintenance helpers for FEC-sealed content.

- place_shards(object_id: [u8; 32], count: usize) -> Vec<Vec<u8>>
  - Returns node IDs for shard placement using trust-weighted proximity.

- provider_advertise_space(free: u64, total: u64)
  - Publishes capacity to the DHT under a well-known key pattern.

- repair_request(object_id: [u8; 32]) -> RepairPlan
  - Returns `RepairPlan { object_id, missing_shards: Vec<usize>, repair_nodes: Vec<Vec<u8>> }`.


## Friend Mesh Backup API

Optional cooperative backup among friends/devices with rotation.

- friend_mesh_plan(data_size: u64, mesh_config: &FriendMeshConfig) -> FriendBackupPlan
  - `FriendMeshConfig { mesh_id: Key, members: Vec<FriendMeshMember>, replication_factor, rotation_schedule }`
  - Returns `FriendBackupPlan { total_shards, shard_size, assignments: Vec<FriendBackupAssignment> }`.


## Virtual Disk API

Every entity (individual, group, organization, channel) can have two virtual disks: private (encrypted) and public (website). This API provides file system operations over the DHT with FEC protection.

### Core Virtual Disk Operations

- disk_create(entity_id: Key, disk_type: DiskType, config: DiskConfig) -> Result<DiskHandle>
  - `DiskType = { Private, Website }`  
  - `DiskConfig { fec_params: FecParams, encryption: EncryptionConfig, cache_policy: CachePolicy }`
  - Creates virtual disk root and initializes metadata

- disk_mount(entity_id: Key, disk_type: DiskType) -> Result<DiskHandle>
  - Mounts existing virtual disk for operations

- disk_write(handle: DiskHandle, path: &str, content: &[u8], metadata: FileMetadata) -> Result<WriteReceipt>
  - Writes file to path with automatic FEC sealing and DHT distribution
  - `FileMetadata { mime_type, permissions, created_at, tags }`

- disk_read(handle: DiskHandle, path: &str) -> Result<Vec<u8>>
  - Reads file, reconstructing from FEC shards if needed

- disk_list(handle: DiskHandle, path: &str, recursive: bool) -> Result<Vec<FileEntry>>
  - Lists directory contents with metadata
  - `FileEntry { path, size, modified_at, file_type, permissions }`

- disk_delete(handle: DiskHandle, path: &str) -> Result<()>
  - Marks file as deleted and schedules shard cleanup

- disk_sync(handle: DiskHandle) -> Result<SyncStatus>
  - Forces synchronization of pending changes to DHT
  - Returns `SyncStatus { pending_writes, conflicts, last_sync }`

### Website Publishing Operations

- website_set_home(handle: DiskHandle, markdown_content: &str, assets: Vec<Asset>) -> Result<()>
  - Sets `home.md` as website entry point with linked assets
  - `Asset { path, content, mime_type }` for images, CSS, etc.

- website_publish(entity_id: Key, website_root: Key) -> Result<PublishReceipt>  
  - Updates entity's IdentityPacket with new website_root
  - Makes website publicly accessible via four-word address

- website_get_manifest(website_root: Key) -> Result<WebsiteManifest>
  - Retrieves website structure and asset references
  - `WebsiteManifest { home_md_key, assets: Vec<AssetRef>, navigation, metadata }`

### Collaborative Operations

- disk_share(handle: DiskHandle, path: &str, permissions: Permissions, members: Vec<Key>) -> Result<ShareToken>
  - Shares file/directory with specific members
  - `Permissions { read, write, admin }` with role-based access

- disk_collaborate(handle: DiskHandle, path: &str, session_id: SessionId) -> Result<CollabSession>
  - Initiates real-time collaborative editing session
  - Returns conflict-free replicated data type (CRDT) session

- disk_resolve_conflict(handle: DiskHandle, conflict: FileConflict, resolution: ConflictResolution) -> Result<()>
  - Resolves file conflicts using specified strategy
  - `ConflictResolution = { TakeLocal, TakeRemote, Merge(strategy), Manual(content) }`

### Advanced Operations

- disk_snapshot(handle: DiskHandle, name: &str) -> Result<SnapshotId>
  - Creates immutable snapshot of current disk state

- disk_restore(handle: DiskHandle, snapshot_id: SnapshotId) -> Result<()>
  - Restores disk to previous snapshot state

- disk_encrypt_for_group(handle: DiskHandle, group_id: Key, mls_key: &[u8]) -> Result<()>
  - Re-encrypts disk content for group access using MLS derived keys

## Virtual Disks and Websites

Every entity (individual, group, organization, channel) can expose two logical disks:

1) Private Disk (entity-scoped, group-encrypted)
   - Root Key: `disk_root = compute_key("disk", entity_id.as_bytes())`
   - Organization: content addressed by path → object key mapping using `ContainerManifestV1` for each root object.
   - Encryption: MLS or group ML-DSA derived symmetric keys; objects are sealed and sharded with FEC `(k,m,shard_size)` across DHT, with optional member-local caches.
   - Access: membership governed; members reconstruct via DHT + local caches.

2) Website Disk (public)
   - Root Key: `website_root` in `IdentityPacketV1` or `compute_key("website", entity_id.as_bytes())` if not set.
   - Convention: `home.md` is the entry file (Markdown-only web). Assets referenced by relative paths resolve to `assets/` keyed objects in the same container or sibling keys.
   - Publishing: write manifests and assets to DHT under context keys, set/refresh `website_root` on identity.
   - Browsing: agents fetch `IdentityPacketV1`, read `website_root`, fetch `ContainerManifestV1` at root, then fetch `home.md` and linked assets.

Addressing Examples
- Individual disk: `disk_root = blake3("disk" || ID)` where `ID = blake3(words)`.
- Group disk: same construction with the group’s `id` from `GroupIdentityPacketV1`.
- Channel disk: derive channel key: `channel_id = compute_key("channel", group_id.as_bytes())` then `disk_root = compute_key("disk", channel_id.as_bytes())`.


## Messaging API (High-Level Service)

The MessagingService coordinates storage, transport, and encryption for direct and group messaging and calls.

Types
- `FourWordAddress` — identity handle (string form of four words)
- `ChannelId`, `ThreadId`, `MessageId` — logical identifiers
- `MessageContent` — rich content (text, reactions, attachments)
- `EncryptedMessage`, `RichMessage`, `DeliveryReceipt`, `DeliveryStatus`

Construction
- new(identity: FourWordAddress, dht_client: DhtClient) -> Result<MessagingService>
  - Wires persistence, PQC key-exchange, transport, and events.

Send & Receive
- send_message(recipients: Vec<FourWordAddress>, content: MessageContent, channel_id: ChannelId, options: SendOptions) -> Result<(MessageId, DeliveryReceipt)>
  - Encrypts per recipient and sends via transport (DHT + direct), stores locally first.

- MessagingService::send_message_to_channel(channel_id: ChannelId, content: MessageContent, options: SendOptions) -> Result<(MessageId, DeliveryReceipt)>
  - Sends message to all members of a channel by resolving recipients from channel membership.
  - Internally calls `send_message()` with resolved recipient list from `channel_recipients()`.

- channel_recipients(channel_id: &ChannelId) -> Result<Vec<FourWordAddress>>
  - Helper function to resolve channel members to their four-word addresses.
  - Loads channel, maps member user_ids to FourWordAddress for messaging.

- subscribe_messages(channel_filter: Option<ChannelId>) -> Receiver<ReceivedMessage>
  - Async stream of inbound messages (decrypted and persisted before delivery).

- get_message_status(message_id: MessageId) -> Result<DeliveryStatus>
- get_message(message_id: MessageId) -> Result<RichMessage>
- mark_user_online(user: FourWordAddress) -> Result<()>
- mark_delivered(message_id: MessageId, recipient: FourWordAddress) -> Result<()>
- process_message_queue() -> Result<()>
- encrypt_message(recipient, channel_id, content) -> Result<EncryptedMessage>
- decrypt_message(encrypted) -> Result<RichMessage>

Realtime A/V Calls
- The messaging/webrtc bridge supports:
  - Direct 1:1 audio/video/screen-share over WebRTC with QUIC transport.
  - Group calls by creating an MLS-secured session; members receive dynamic group endpoints from `GroupForwardsV1`.
  - Signaling exchanged as messages; media flows are direct peer-to-peer when possible.


## Agent Decision Trees

### When to Use Which API

**For Identity Management:**
- New user? → `identity_claim()` + `identity_publish_endpoints_signed()`  
- User connecting from new device? → `device_publish_forward_signed()`
- Need to find user? → `identity_fetch()` + four-word address resolution

**For Messaging:**
- 1:1 chat? → `MessagingService::send_message()` with single recipient
- Group chat? → Group API first, then `MessagingService` with group context  
- File attachment? → Virtual Disk API to store, then send reference via messaging
- Need offline delivery? → Messages automatically queued in DHT

**For Real-Time Communication:**  
- Voice/video call? → Real-Time Media API `call_initiate()`
- Screen sharing? → `media_toggle_screen_share()` during active call
- Group conference? → `group_call_create()` within existing group
- Recording needed? → `call_record()` with participant consent

**For File Storage:**
- Private group files? → Virtual Disk API with `Private` disk type
- Public website? → Virtual Disk API with `Website` disk type  
- Need backup? → Friend Mesh Backup API for redundancy
- Large files? → Storage Control API for optimal shard placement

### API Interaction Patterns

**Pattern 1: User Onboarding Flow**
```
identity_claim() → identity_publish_endpoints_signed() → 
device_publish_forward_signed() → MessagingService::new()
```

**Pattern 2: Group Creation with Storage**  
```
group_identity_create() → group_identity_publish() → 
disk_create(Private) → group_forwards_put()
```

**Pattern 3: Collaborative Document Editing**
```
disk_mount() → disk_collaborate() → Real-Time Media API (optional voice) →
disk_sync() → disk_snapshot() (for versioning)
```

**Pattern 4: Public Website Publishing**
```
disk_create(Website) → website_set_home() → 
website_publish() → identity_publish_endpoints_signed()
```

## Common Patterns

### Best Practices for Agents

**Security First:**
- Always validate four-word addresses before computing keys
- Use canonical signing bytes for identity and group operations  
- Never persist plaintext keys - use secure storage
- Verify signatures on all critical operations

**Error Handling:**
- All APIs return `Result<T, E>` - handle errors explicitly
- Use structured error types for debugging
- Implement retry logic for network operations
- Log structured events for observability

**Performance Optimization:**
- Cache identity lookups locally with TTL
- Use quorum=1 for best-effort reads, quorum=majority for critical writes
- Batch multiple operations when possible
- Use friend mesh backup for frequently accessed group content

**Network Efficiency:**
- Reuse QUIC connections where possible
- Use appropriate stream classes for telemetry
- Enable compression for large content transfers
- Monitor call quality and adjust media settings dynamically

### Troubleshooting Guide

**Common Issues:**

1. **Identity claim fails:**
   - Check four-word validation against FWN dictionary
   - Verify ML-DSA signature over canonical bytes
   - Ensure words are properly joined with '-'

2. **Group operations fail:**  
   - Verify membership_root matches sorted member IDs
   - Check group signature against canonical message
   - Ensure all members have valid identity packets

3. **File operations slow:**
   - Check FEC parameters (k, m values)
   - Verify shard placement across trusted nodes
   - Consider local caching for frequently accessed content

4. **Call quality issues:**
   - Monitor `call_get_stats()` for packet loss/latency
   - Try `media_adjust_quality(Auto)` for adaptive streaming
   - Check if `call_enable_noise_cancellation()` helps

## Example: Building "Communitas"

Communitas is a large-scale, P2P collaboration app blending WhatsApp (messaging/calls), Dropbox (storage/sync), Slack (channels/threads), and a new Markdown-based web. It is phishing-resistant (four-word networking) and AI-friendly (structured APIs and explicit semantics).

Core Features
- Identity: users and groups claim four-word addresses; groups carry membership roots and published forwards.
- Messaging: 1:1 and group threads with reactions, attachments, and threads.
- Calls: direct audio/video/screen-share with group calls via MLS sessions.
- Storage: end-to-end encrypted “virtual disks” per entity (user/group/channel) with DHT + local caches and FEC-sealed containers.
- Web: every entity can publish a public Markdown site (`home.md`) at its website disk root.

High-Level Flows
1) User Onboarding
   - Generate ML-DSA keypair; select four words; call `identity_claim()` with signature over words.
   - Publish device forwards (`device_publish_forward_signed`) and endpoints (`identity_publish_endpoints_signed`).

2) Creating a Group
   - Select group words; gather initial members (`MemberRef { member_id, member_pk }`).
   - Call `group_identity_create()` and then `group_identity_publish()`.
   - Store `GroupForwardsV1` to advertise callable members.

3) Private Disk Setup (Group)
   - Compute `disk_root = compute_key("disk", group_id.as_bytes())`.
   - Create a root `ContainerManifestV1` with FEC parameters and encrypted `sealed_meta` (MLS key).
   - Place shards with `place_shards(object_id, k+m)` and upload to DHT; optionally seed local caches.

4) Public Website
   - Compute or fetch `website_root`; create a container with `home.md` and assets.
   - Write container manifest under `compute_key("manifest", object_root)` and set `website_root` in identity.
   - Resolution: clients fetch identity → `website_root` → manifest → fetch `home.md` and linked assets.

5) Messaging and Calls
   - For 1:1: create or join `ChannelId` (derived from pair’s IDs), call `send_message()` and listen on `subscribe_messages()`.
   - For groups: derive `ChannelId` from group id; agents retrieve `GroupForwardsV1` to locate members and initiate MLS-secured calls; media flows over WebRTC/QUIC.

6) Friend Mesh Backup (Optional)
   - Maintain resilient copies by planning with `friend_mesh_plan()`; rotate shard assignments on schedule.

Sample Pseudocode (Agent)
```rust
// 1) Claim identity
let words = ["river".into(), "spark".into(), "honest".into(), "lion".into()];
let (pk, sk) = mldsa_generate();
let sig = mldsa_sign(&sk, words.join("-"));
identity_claim(words.clone(), PubKey::new(pk.clone()), Sig::new(sig)).await?;

// 2) Publish endpoints and forwards
let endpoints = vec![NetworkEndpoint { ipv4: Some(("203.0.113.10".into(), 443)), ipv6: None, fw4: None, fw6: None }];
let ep_sig = sign_endpoints(&sk, &id_key, &pk, &endpoints);
identity_publish_endpoints_signed(id_key.clone(), endpoints, ep_sig).await?;
device_publish_forward_signed(id_key.clone(), Forward::quic("203.0.113.10:443"), delegated_sig).await?;

// 3) Create group and publish forwards
let (g_pkt, g_kp) = group_identity_create(group_words, members)?;
group_identity_publish(g_pkt.clone()).await?;
group_forwards_put(&GroupForwardsV1 { v: 1, endpoints: endpoints_for_members, proof: None }, &g_pkt.id.as_bytes()[..], &policy).await?;

// 4) Store website container
let manifest = ContainerManifestV1 { v: 1, object: website_root, fec: FecParams { k: 8, m: 4, shard_size: 65536 }, assets: vec![home_md_key, css_key], sealed_meta: None };
container_manifest_put(&manifest, &policy).await?;

// 5) Messaging
let svc = MessagingService::new(my_fw_address, dht).await?;
let (_id, receipt) = svc.send_message(vec![peer_fw], MessageContent::Text("Hi".into()), channel_id, SendOptions::default()).await?;
```


## Comprehensive Usage Examples

### Identity Website Root Update

```rust
use saorsa_core::api::*;
use saorsa_core::quantum_crypto::{MlDsa65, MlDsaOperations};

// Update an identity's website root
let id_key = Key::from([1u8; 32]);
let website_root = Key::from([2u8; 32]);
let ml = MlDsa65::new();
let (pk, sk) = ml.generate_keypair().unwrap();

// Build canonical message
let mut msg = Vec::new();
msg.extend_from_slice(CANONICAL_IDENTITY_WEBSITE_ROOT);
msg.extend_from_slice(id_key.as_bytes());
msg.extend_from_slice(pk.as_bytes());
let website_root_cbor = serde_cbor::to_vec(&website_root).unwrap();
msg.extend_from_slice(&website_root_cbor);

// Sign and update
let sig = ml.sign(&sk, &msg).unwrap();
identity_set_website_root(id_key, website_root, Sig::new(sig.as_bytes().to_vec())).await?;
```

### Group Membership Update

```rust
use saorsa_core::api::*;

// Update group membership
let group_id = Key::from([1u8; 32]);
let new_members = vec![
    MemberRef {
        member_id: Key::from([2u8; 32]),
        member_pk: vec![1, 2, 3],
    }
];

// Get canonical signing bytes
let membership_root = compute_membership_root(&new_members);
let sign_bytes = group_identity_canonical_sign_bytes(&group_id, &membership_root);

// Sign with group key
let ml = MlDsa65::new();
let group_pk = vec![4, 5, 6]; // From group creation
let group_sk = ml.generate_keypair().unwrap().1; // In practice, use stored key
let sig = ml.sign(&group_sk, &sign_bytes).unwrap();

// Update membership
group_identity_update_members_signed(
    group_id,
    new_members,
    group_pk,
    Sig::new(sig.as_bytes().to_vec())
).await?;
```

### Virtual Disk Operations

```rust
use saorsa_core::virtual_disk::*;

// Create and use a virtual disk
let entity_id = Key::from([1u8; 32]);
let config = DiskConfig::default();

// Create disk
let handle = disk_create(entity_id, DiskType::Private, config).await?;

// Write file
let content = b"Hello, Virtual Disk!";
let metadata = FileMetadata::default();
disk_write(&handle, "hello.txt", content, metadata).await?;

// Read file
let read_content = disk_read(&handle, "hello.txt").await?;
assert_eq!(read_content, content);

// List directory
let files = disk_list(&handle, ".", false).await?;
println!("Files: {:?}", files);

// Sync changes
let sync_status = disk_sync(&handle).await?;
println!("Sync status: {:?}", sync_status);
```

### Website Publishing

```rust
use saorsa_core::virtual_disk::*;

// Create and publish a website
let entity_id = Key::from([1u8; 32]);
let handle = disk_create(entity_id.clone(), DiskType::Website, DiskConfig::default()).await?;

// Set home page with assets
let markdown = "# Welcome\n\nThis is my website.";
let assets = vec![
    Asset {
        path: "style.css".to_string(),
        content: b"body { font-family: sans-serif; }".to_vec(),
        mime_type: "text/css".to_string(),
    }
];

website_set_home(&handle, markdown, assets).await?;

// Publish website
let website_root = Key::from([2u8; 32]);
let receipt = website_publish(entity_id, website_root).await?;
println!("Website published: {:?}", receipt);
```

### Channel Messaging

```rust
use saorsa_core::messaging::service::*;
use saorsa_core::messaging::types::*;

// Send message to channel
let channel_id = ChannelId::new();
let content = MessageContent::Text("Hello, channel!".to_string());
let options = SendOptions::default();

// Send to all channel members
let messaging = MessagingService::new(four_word_address, dht_client).await?;
let (message_id, receipt) = messaging.send_message_to_channel(
    channel_id,
    content,
    options
).await?;

// Get channel recipients
let recipients = channel_recipients(&channel_id).await?;
println!("Channel has {} recipients", recipients.len());
```

### Group Member Management

```rust
use saorsa_core::api::*;

// Add member to group
let group_id = Key::from([1u8; 32]);
let new_member = MemberRef {
    member_id: Key::from([2u8; 32]),
    member_pk: vec![1, 2, 3],
};

// Sign with group key (simplified)
let group_pk = vec![4, 5, 6];
let group_sig = Sig::new(vec![7, 8, 9]); // In practice, compute proper signature

group_member_add(group_id, new_member, group_pk, group_sig).await?;

// Remove member
let member_to_remove = Key::from([2u8; 32]);
group_member_remove(group_id, member_to_remove, group_pk, group_sig).await?;
```

### Group Epoch Bump

```rust
use saorsa_core::api::*;

// Bump group epoch
let group_id = Key::from([1u8; 32]);
let proof = Some(vec![1, 2, 3]); // Optional proof data
let group_pk = vec![4, 5, 6];
let group_sig = Sig::new(vec![7, 8, 9]); // Proper signature required

group_epoch_bump(group_id, proof, group_pk, group_sig).await?;
```

## Anti-Phishing and Name Safety

- Four-word addresses are validated against the FWN dictionary and encoding. Because words map through a checksum-bearing scheme, close-word collisions are minimized and detectable.
- Display of endpoints and identities defaults to four-word forms (FW4/FW6) where possible.
- Agents should treat any UI string not derived from four-word encodings as untrusted.


## Error Handling and Telemetry

- All APIs return explicit `Result<T, E>`; production code never panics. Errors include descriptive messages and can carry machine-parsable codes.
- `tracing` emits JSON-structured events for: DHT puts/gets, auth failures, timeouts, stream class usage, and message delivery outcomes.

### Extended Error Types

The following error variants have been added to support new API functionality:

**Identity Errors:**
- `InvalidSignature` - Signature verification failed
- `InvalidCanonicalBytes` - Canonical message format invalid
- `MembershipConflict` - Group membership operation conflict
- `MissingGroupKey` - Required group key not found
- `WebsiteRootUpdateRefused` - Website root update rejected

**Usage Examples:**
```rust
use saorsa_core::error::{P2PError, IdentityError};

// Handle identity-specific errors
match result {
    Err(P2PError::Identity(IdentityError::InvalidSignature)) => {
        // Handle signature verification failure
        log::warn!("Signature verification failed for identity operation");
    }
    Err(P2PError::Identity(IdentityError::WebsiteRootUpdateRefused)) => {
        // Handle website root update rejection
        log::error!("Website root update was refused");
    }
    // ... other error handling
}
```


## Security Notes

- Identity auth: ML-DSA-65 signatures; signatures over canonical content prevent malleability.
- Content encryption: PQC-friendly symmetric crypto (ChaCha20-Poly1305 via saorsa-pqc). Group content can use MLS session keys.
- Sharding: FEC `(k,m,shard_size)` improves resiliency; shard placement uses trust-weighted selection; repairs planned via `repair_request()` and optional friend-mesh rotation.
- Keys and secrets must never be persisted in plaintext. Use secure storage and zeroization where applicable.


## Compatibility and Versioning

- All top-level records are versioned (`v: u8`).
- New fields are added in a backwards-compatible manner. Unknown fields must be ignored by agents.
- Wire-compatibility is ensured through CBOR encoding of canonical records and explicit signature bytes.


## Quick Reference (Calls)

- Identity: `identity_claim`, `identity_fetch`, `identity_publish_endpoints_signed`, `identity_set_website_root`, `device_publish_forward`, `device_publish_forward_signed`, `device_subscribe`, `group_identity_canonical_sign_bytes`.
- Groups: `group_identity_create`, `group_identity_publish`, `group_identity_fetch`, `group_identity_update_members_signed`, `group_member_add`, `group_member_remove`, `group_epoch_bump`, `group_forwards_put`, `group_forwards_fetch`, `group_put`, `group_fetch`.
- DHT: `dht_put`, `dht_get`, `dht_watch`, `set_dht_instance`.
- Virtual Disk: `disk_create`, `disk_mount`, `disk_write`, `disk_read`, `disk_list`, `disk_delete`, `disk_sync`, `website_set_home`, `website_publish`, `website_get_manifest`, `disk_share`, `disk_collaborate`, `disk_resolve_conflict`, `disk_snapshot`, `disk_restore`, `disk_encrypt_for_group`.
- Messaging: `MessagingService::new`, `send_message`, `send_message_to_channel`, `channel_recipients`, `subscribe_messages`, `get_message_status`, `get_message`, `mark_user_online`, `mark_delivered`, `process_message_queue`, `encrypt_message`, `decrypt_message`.
- Routing & Trust: `record_interaction`, `eigen_trust_epoch`, `route_next_hop`.
- Transport: `quic_connect`, `quic_open`.
- Storage Control: `place_shards`, `provider_advertise_space`, `repair_request`.
- Friend Mesh: `friend_mesh_plan`.


## Implementation Notes for Agents

- Always validate four-word inputs before computing keys.
- Use canonical signing bytes as described for identities, endpoints, and groups.
- For websites, prefer immutable content addresses in manifests; update manifests atomically and then update `website_root` to point to the new object root.
- For large files, use `ContainerManifestV1` + chunked/FEC-sealed storage; place shards via `place_shards` and cache locally for fast group reads.
- For calls, prefer the MessagingService call flows; only reach for raw QUIC when building bespoke transports.

