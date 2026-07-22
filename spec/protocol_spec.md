# DPVL Protocol Specification v1.0

## 1. Message Types

| Type ID | Message            | Direction          |
|---------|--------------------|--------------------|
| 0x01    | PATH_CLAIM         | Source → Dest      |
| 0x02    | PROBE              | Source → Dest      |
| 0x03    | PROBE_ACK          | Dest → Source      |
| 0x04    | VERIFICATION_TOKEN | Any → Next Hop     |
| 0x05    | CHALLENGE          | Dest → Source      |
| 0x06    | CHALLENGE_RESPONSE | Source → Dest      |
| 0x07    | SKETCH_SNAPSHOT    | Any → VE           |
| 0x08    | AUDIT_SUBMISSION   | Node → VA          |

## 2. Wire Format

All messages use TLV (Type-Length-Value) encoding with a 4-byte header.

### 2.1 Common Header (4 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Version (4)  |  Msg Type (8) |          Length (16)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.2 PATH_CLAIM (0x01)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Path ID (32)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Claimant ID (32)                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Timestamp (32)                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   TTL (16)      |   Hop Count (8)  |  Nonce (8)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Path[...] (variable, hop_count * 32-bit node IDs)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Signature (variable, 256-512 bytes)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.3 PROBE (0x02)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Path ID (32)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Nonce (32)                                                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Hop Count (8) |   Accumulated Tag (variable)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.4 VERIFICATION_TOKEN (0x04)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Path ID (32)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Seq Number (32)                                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Node ID (32)                                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   HMAC (256)                                                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.5 CHALLENGE (0x05)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Path ID (32)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Window Start (32)                                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Window End (32)                                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Challenge Nonce (32)                                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## 3. Cryptographic Primitives

| Operation       | Algorithm                   | Key Size |
|-----------------|----------------------------|----------|
| Claim Signature | Ed25519                    | 32 bytes |
| Probe Tag       | HMAC-SHA256                | 32 bytes |
| Token HMAC      | HMAC-SHA256                | 32 bytes |
| Node Identity   | SHA256(public_key)         | 32 bytes |
| Sketch Hash     | SipHash-2-4                | 8  bytes |

## 4. Verification Authority (VA) Protocol

- Registration: `REGISTER(node_id, public_key, as_number)` → signed certificate
- Audit submission: `AUDIT(path_id, window_start, window_end, cuckoo_filter_data)` → ACK
- Key revocation: `REVOKE(node_id, timestamp)` → broadcast to all peers

## 5. Bloom Filter / Sketch Parameters

| Parameter           | Value      |
|---------------------|------------|
| Sketch type         | Count-Min Sketch |
| Width               | 2^16 = 65536 |
| Depth (hash count)  | 4          |
| Cell size           | 4 bytes    |
| Total sketch size   | 1 MB       |
| Decay interval      | 60 seconds |
