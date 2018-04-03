# OTRv4 Prekey Server

```
Disclaimer

This protocol specification is a draft.
```

OTRv4 Prekey Server provides an specification for OTRv4 [\[1\]](#references)
protocol when it needs an untrusted central Prekey Server to store prekey
messages.

## Table of Contents

1. [High Level Overview](#high-level-overview)
1. [Assumptions](#assumptions)
1. [Prekey Server Specifications](#prekey-server-specifications)
1. [Notation and Parameters](#notation-and-parameters)
   1. [Notation](#notation)
   1. [Elliptic Curve Parameters](#elliptic-curve-parameters)
   1. [Key Derivation Functions](#key-derivation-functions)
1. [Data Types](#data-types)
   1. [Encoded Messages](#encoded-messages)
   1. [Public keys and Fingerprints](#public-keys-and-fingerprints)
   1. [Shared Session State](#shared-session-state)
   1. [Prekey Server's Identifier](#prekey-servers-identifier)
1. [Key Management](#key-management)
   1. [Shared secrets](#shared-secrets)
   1. [Generating Shared Secrets](#generating-shared-secrets)
1. [Interactive DAKE](#interactive-dake)
   1. [DAKE-1 Message](#dake-1-message)
   1. [DAKE-2 Message](#dake-2-message)
   1. [DAKE-3 Message](#dake-3-message)
   1. [Prekey Publication Message](#prekey-publication-message)
   1. [Storage Information Message](#storage-information-message)
   1. [Storage Status Message](#storage-status-message)
   1. [No Prekey-Messages on Storage Message](#no-prekey-messages-on-storage-message)
   1. [Success Message](#success-message)
   1. [Failure Message](#failure-message)
1. [State machine](#state-machine)
1. [Publishing Prekey Messages](#publishing-prekey-messages)
1. [Retrieving Prekey Messages](#retrieving-prekey-messages)
1. [Query the Prekey Server for its storage status](#query-the-prekey-server-for-its-storage-status)
1. [A Prekey Server for OTRv4 over XMPP](#a-prekey-server-for-otrv4-over-xmpp)
   1. [Discovering a prekey service](#discovering-a-prekey-service)
   1. [Discovering the features supported by a prekey service](#discovering-the-features-supported-by-a-prekey-service)
   1. [Publishing prekeys to the service](#publishing-prekeys-to-the-service)
   1. [Obtaining information about your prekeys from the service](#obtaining-information-about-your-prekeys-from-the-service)
      1. [Retrieving published prekeys from a prekey service](#retrieving-published-prekeys-from-a-prekey-service)
1. [Detailed example of the prekey server over XMPP](#detailed-example-of-the-prekey-server-over-xmpp)
1. [Attacks](#attacks)
   1. [KCI attacks and the unstrusted prekey server](#kci-attacks-and-the-unstrusted-prekey-server)
1. [References](#references)

## High Level Overview

The OTRv4 Prekey Server specification defines a way by which parties can
publish, store and retrieve prekey messages from an untrusted Prekey Server.
A Prekey message contains the publisher's User Profile, the publisher's Prekey
Profile and two one-time use ephemeral public prekey values, as defined in the
OTRv4 specification [\[1\]](#references). These prekey messages are used for
starting offline conversations.

In order to perform offline conversations, OTRv4 specification defines a
non-interactive DAKE, which is derived from the XZDH protocol. It begins when
Alice, who wants to initiate an offline conversation with Bob, asks an untrusted
Prekey Server for Bob's prekey messages. These prekey messages have previously
been stored in the Prekey Server by Bob.

This document aims to describe how the untrusted Prekey Server can be used to
securely publish, store and retrieve prekey messages.

## Assumptions

OTRv4 Prekey Server specification does not fully protect against an active
attacker performing Denial of Service attacks.

During the DAKE performed by the publisher with the Prekey Server, the network
model provides in-order delivery of messages.

The Prekey Server should support multiple prekey messages from different/future
OTR versions, starting with version 4.

## Prekey Server Specifications

The Prekey Server used in this specification should be considered untrusted.
This means that a malicious server could cause communication between parties to
fail (e.g. by refusing to deliver prekey messages).

The Prekey Server must have these capabilities:

- Receive prekey messages and store them. Inform that this operation have failed
  or has been successful.
- Deliver prekey messages previously stored.
- Inform the publisher about how many prekey messages are stored for them.
- Inform the retriever when there are no prekey messages from an specific party.

The Prekey Server expects to only receive messages on the same network
authenticated clients use to exchange messages. This means that a message
received should be from the same network the publisher is believed to have
been authenticated to.

Although this specification defines an specific behavior from the Prekey Server
(e.g., by specifying that prekey messages submissions should be validated by the
Prekey Server), clients should not rely on this prescribed behavior, as the
Prekey Server is unstrusted. It must be taken into account that a misbehavior
from the Prekey Server can potentially affect the security of the whole OTRv4
protocol. For this reason, verifications must be performed by clients as well,
even though the Prekey Server should be expected to perform them.

Note that prekey messages submissions to the untrusted Prekey Server have to be
authenticated. If they are not authenticated, then malicious users can perform
denial-of-service attacks. To preserve the deniability of the overall OTRv4
protocol, prekeys messages should never be digitally signed. The best approach
is to authenticate prekey message uploads using a DAKEZ exchange between the
publisher and the Prekey Server, which preserves deniability.

In order to correctly perform the DAKEZ with the publisher, the untrusted Prekey
Server should be able to correctly generate ephemeral ECDH keys and long-term
ed488-EdDSA keys.

When this untrusted Prekey Server runs out of prekey messages, a "No
Prekey-Messages on Storage" message should be returned, as define in its
[section](#no-prekey-messages-on-storage-message). A default prekey message
should not be returned until new prekey messages are uploaded to the untrusted
server as the consequences to participation deniability with this technique are
currently undefined and, thus, risky. Nevertheless, with this, the OTRv4
protocol can be subject of DoS attacks when a Prekey Server is compromised or
the network is undermined to return a "No Prekey-Messages on Storage" message
from the Prekey Server.

Notice that the Prekey Server should be able to support future versions,
starting from version 4. This means that the Prekey Sever will accept prekey
ensembles with different versions. For this, the header on the prekey messages
should remain the same:

```
Protocol version (SHORT)
  The version number of the protocol, e.g, 0x0004 for OTRv4.

Message type (BYTE)
  The message type, e.g., 0x0F for OTRv4.

Prekey Message Indentifier (INT)
  A prekey message id used for local retrieval.

Prekey owner's instance tag (INT)
  The instance tag of the client that created the prekey message.
```

## Notation and Parameters

### Notation

OTRv4 Prekey Server specification uses the same notation as the OTRv4
specification, defined in the section
[Notation](https://github.com/otrv4/otrv4/blob/master/otrv4.md#notation).

Notice that scalars and secret/private keys are in lower case, such as `x`
or `y`. Points and public keys are in upper case, such as `P` or `Q`.

The concatenation of byte sequences `I` and `J` is `I || J`. In this case, `I`
and `J` represent a fixed-length byte sequence encoding of the respective
values.

### Elliptic Curve Parameters

The OTRv4 Prekey Server specification uses the Ed448-Goldilocks
[\[3\]](#references) elliptic curve [\[4\]](#references), with the same
parameters as those defined in the
[Elliptic Curve Parameters](https://github.com/otrv4/otrv4/blob/master/otrv4.md#elliptic-curve-parameters)
section of the OTRv4 specification.

### Key Derivation Functions

The following key derivation function is used in this specification:

```
  KDF(usageID || values, size) = SHAKE-256("OTRv4" || usageID || values, size)
```

The `size` first bytes of the SHAKE-256 output for input
`"OTRv4-Prekey-Server" || usageID || values` are returned.

Unlike SHAKE standard, notice that the output size (`size`) here is defined in
bytes.

## Data Types

OTRv4 Prekey Server Specification uses many of the data types already specified
in the OTRv4 specification, as defined in section
[Data Types](https://github.com/otrv4/otrv4/blob/master/otrv4.md#data-types)

OTRv4 Prekey Server Specification also uses the following data type:

```
Prekey Server's Identifier (PREKEY-SERVER-ID):
  Detailed in "Server's Identifier" section
```

### Encoded Messages

OTRv4 Prekey Server messages must be base-64 encoded. To transmit one of these
messages, construct an ASCII string: the six bytes "?OTRP:", the base-64
encoding of the binary form of the message and the byte ".".

### Public keys and Fingerprints

OTR users have long-lived public keys that they use for authentication (but not 
for encryption). The untrusted Prekey Server has one as well. They are generated
as defined in the "Public keys, Shared Prekeys and Fingerprints" section of the
OTRv4 specification.

Public keys have fingerprints, which are hex strings that serve as identifiers
for the public key. The full OTRv4 fingerprint is calculated by taking the
SHAKE-256 hash of the byte-level representation of the public key. The long-term
public keys for the Prekey Server have fingerprints as well. The fingerprint is
generated as:

* The first 56 bytes from the `KDF(0x00 || byte(H), 56)` (224-bit security
  level).

### Shared Session State

A Shared Session State is needed for this specification for the same reasons
stated in the
[Shared Session State](https://github.com/otrv4/otrv4/blob/master/otrv4.md#shared-session-state)
section of the OTRv4 specification. It is used to authenticate contexts to
prevent attacks that rebind the DAKE transcript into different contexts. This
value is only needed for the interactive DAKE performed by the publishing party
and the untrusted Prekey Server.

In the case that this interactive DAKE happens over XMPP, this must be:

```
  phi = publisher's bare JID || servers's bare JID
```

For example:

```
  phi = "alice@jabber.net" || "prekeys.xmpp.org"
```

### Prekey Server's Identifier

For the interactive DAKE performed by a publisher and the untrusted Prekey
Server, an identifier is needed. This value will be denoted as "Server's
Identifier".

In any case, it should be hash of the Prekey Server's identity concatenated with
the Prekey Server's long-term public key's fingerprint.

```
Prekey Server's Indentifier (PREKEY-SERVER-ID):
  Prekey Server's identity (DATA)
  Fingerprint (DATA)
```

For a Prekey Server that uses XMPP, this must be the Prekey Server's bare JID
(for example, prekey.xmpp.org) and its long-term public key's fingerprint:

```
  Prekey Server's identifier = "prekey.xmpp.org" || "8625CE01F8D06586DC5B58BB1DC7D9C74F42FB07"
```

## Key Management

In the interactive DAKE between the publisher and the Prekey Server, long-term
Ed448 keys and ephemeral Elliptic Curve Diffie-Hellman (ECDH) keys are used.
Notice that if this DAKE is only used for deniable authentication, the shared
secret derived during the DAKE should be discarded. Nevertheless, this shared
secret can be used with the Double Ratchet Algorithm to either encrypt the
channel or by untrusted Prekey Server to encrypt the stored prekey messages
(note that the Prekey Server, nevertheless, must handle them out decrypted to
the retrieving party).

### Shared secrets

```
  SK_ecdh:
    The serialized ECDH shared secret computed from an ECDH exchange, serialized
    as a 'POINT', as define in "Encoding and Decoding" section of the OTRv4
    protocol.
  SK:
    The Shared secret is the shared secret derived from the ECDH shared secret:
    'KDF(0x01 || SK_ecdh)'.
```

### Generating Shared Secrets

```
  ECDH(a, B)
    B * cofactor
    SK_ecdh = a * B
    if SK_ecdh == 0 (check that it is an all-zero value)
       return error
    else
       return SK_ecdh
```

Check, without leaking extra information about the value of `SK_ecdh`, whether
`SK_ecdh` is the all-zero value and abort if so, as this process involves
contributory behavior. Contributory behaviour means that both parties' private
keys contribute to the resulting shared key. Since Ed448 have a cofactor of 4,
an input point of small order will eliminate any contribution from the other
party's private key. This situation can be detected by checking for the
all-zero output.

## Interactive DAKE

As previously stated, prekey submissions (publishing) have to be authenticated.
If they are not authenticated, then malicious users can perform
denial-of-service attacks. To preserve the deniability of the overall OTRv4
protocol, they are authenticated using a DAKEZ [\[3\]](#references) exchange
between the publisher and the Prekey Server, which preserves deniability.

The following parameters are expected to be generated beforehand:

* `(sk_a, Ha)`: Alice's long-term keypair. As defined in section
   [Public keys, Shared Prekeyes and Fingerprints](https://github.com/otrv4/otrv4/blob/master/otrv4.md#public-keys-shared-prekeys-and-fingerprints)
   of the OTRv4 protocol.
* `(sk_s, Hs)`: Server's long-term keypair. As defined in section
   [Public keys, Shared Prekeyes and Fingerprints](https://github.com/otrv4/otrv4/blob/master/otrv4.md#public-keys-shared-prekeys-and-fingerprints)
   of the OTRv4 protocol.
* `Alices_User_Profile`: Alice's User Profile. As defined in section
   [Creating a User Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#creating-a-user-profile)
   of the OTRv4 protocol.
* `Prekey Servers_Identifier`: the Prekey Server's identifier.

Alice is also expected to receive beforehand the Prekey Server's identity and
its long-term public key, so they can be manually verified by her.

Alice will be initiating the DAKEZ with the Prekey Server:

**Alice**

1. Generates a DAKE-1 message, as defined in [DAKE-1 Message](#dake-1-message)
   section.
1. Sends the DAKE-1 message to the Prekey Server.

**Prekey Server**

1. Receives a DAKE-1 message from Alice:
    * Verifies the DAKE-1 message as defined in the
      [DAKE-1 message](#dake-1-message) section. If the verification fails
      (for example, if Alice's public key -`I`- is not valid), rejects
      the message and does not send anything further. // TODO: send a failure?
1. Generates a DAKE-2 message, as defined in
   [DAKE-2 Message](#dake-2-message) section.
1. Calculates the Shared secret (`SK`):
   * `SK = KDF(0x01 || ECDH(s, I))`.
   * Securely erases `s`.
1. Sends Alice the DAKE-2 message (see [DAKE-2 Message](#dake-2-message)
   section).

**Alice**

1. Receives the DAKE-2 message from the Prekey Server.
1. Retrieves the ephemeral public keys from the Prekey Server (encoded in the
   DAKE-2 message):
    * Validates that the received ECDH ephemeral public key `S` is on curve
      Ed448, as defined in section
      [Verifying that a point is on the curve](#https://github.com/otrv4/otrv4/blob/master/otrv4.md#verifying-that-a-point-is-on-the-curve)
      section of the OTRv4 protocol. If the verification fails, she rejects the
      message and does not send anything further.
1. Verifies the DAKE-2 message as defined in the
   [DAKE-2 message](#dake-2-message) section.
1. Creates a DAKE-3 message (see [DAKE-3 Message](#dake-3-message) section).
1. Calculates the Shared secret (`SK`):
   * `SK = KDF(0x01 || ECDH(i, S))`.
   * Securely erases `i`.
1. Calculates the Prekey MAC key: `prekey_mac_k = KDF(0x08 || SK, 64)`.
1. Creates a message (`msg`):
   1. If she wants to publish prekey messages, she creates a "Prekey publication
      message", as defined in its [section](#prekey-publication-message).
   1. If she want to retrieve storage information, she creates a "Storage
      information request message", as defined in its
      [section](#storage-information-message).
1. Securely deletes the Prekey MAC key.
1. Attaches the corresponding `msg` to the DAKE-3 message, and sends it.

**Prekey Server**

1. Receives the DAKE-3 message from Alice:
   * Verifies the DAKE-3 message as defined in the
     [DAKE-3 message](#dake-3-message) section. If something fails, the server
     rejects the message and does not send anything further.
1. Retrieves the `msg` attached to the DAKE-3 message:
   1. If this is a "Prekey publication message":
      * Uses the sender's instance tag from the DAKE-3 message as the receiver's
        instance tag and checks that is equal to the previously seen.
      * Calculates the Prekey MAC key: `prekey_mac_k = KDF(0x08 || SK, 64)`.
      * Computes the Prekey MAC: `KDF(0x09 ∥ prekey_mac_k || message type ||
        N || prekey messages, 64)`. Checks that it is
        equal to the one received in the Prekey publication message. If it is
        not, the server aborts the DAKE and sends a "Failure Message", as
        defined in its [section](#failure-message).
      * Checks that `N` corresponds to the number of concatenated prekey
        messages. If it is not, aborts the DAKE and sends a "Failure Message",
        as defined in its [section](#failure-message).
      * Stores each prekey message if there is enough space in the Prekey
        Server's storage.
      * Sends a "Success Message", as defined in its [section](#success-message).
   1. If this is a "Storage information request message":
      * Responds with a "Storage Status Message", as defined in its
        [section](#storage-status-message).

### DAKE-1 Message

This is the first message of the DAKE. It is sent to commit to a choice of a
ECDH key.

A valid DAKE-1 message is generated as follows:

1. Generate an ephemeral ECDH key pair, as defined in the
   [Generating ECDH and DH keys](https://github.com/otrv4/otrv4/blob/master/otrv4.md#generating-ecdh-and-dh-keys)
   section of the OTRv4 specification (ignore the generation of DH keys from
   this section):
   * secret key `i` (57 bytes).
   * public key `I`.
2. Generate a 4-byte instance tag to use as the sender's instance tag.
   Additional messages in this conversation will continue to use this tag as the
   sender's instance tag. Also, this tag is used to filter future received
   messages. Messages intended for this instance of the client will have this
   number as the receiver's instance tag.
3. Concatenate the User Profile previously generated.

To verify a DAKE-1 message:

3. Validate the User Profile, as defined in
   [Validating a User Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-user-profile)
   section of the OTRv4 specification.
2. Verify that the point `I` received is on curve Ed448. See
   [Verifying that a point is on the curve](https://github.com/otrv4/otrv4/blob/master/otrv4.md#verifying-that-a-point-is-on-the-curve)
   section of the OTRv4 specification for details.

An DAKE-1 message is an OTRv4 Prekey Server message encoded as:

```
Message type (BYTE)
  The message has type 0x01.

Sender's instance tag (INT)
  The instance tag of the person sending this message.

Sender's User Profile (USER-PROF)
  As described in the section "Creating a User Profile" of the OTRv4
  specification.

I (POINT)
  The ephemeral public ECDH key.

```

### DAKE-2 Message

This is the second message of the DAKEZ. It is sent to commit to a choice of a
ECDH ephemeral key, and to acknowledge the publisher's ECDH ephemeral key.
This acknowledgment includes a validation that the publisher's ECDH key is on
curve Ed448.

A valid Auth-R message is generated as follows:

1. Generate an ephemeral ECDH key pair, as defined in the
   [Generating ECDH and DH keys](https://github.com/otrv4/otrv4/blob/master/otrv4.md#generating-ecdh-and-dh-keys)
   section of the OTRv4 specification (ignore the generation of DH keys from
   this section):
   * secret key `s` (57 bytes).
   * public key `S`.
2. Compute
   `t = 0x00 || KDF(0x02 || Alices_User_Profile, 64) ||
    KDF(0x03 || Servers_Identifier, 64) || I || S || KDF(0x04 || phi, 64)`.
   `phi` is the shared session state as mention in its
   [section](#shared-session-state). `Servers_Identifier` is the server's
   identifier as mention in its [section](#servers-identifier).
3. Compute `sigma = RSig(H_s, sk_hs, {H_a, H_s, I}, t)`. See
   [Ring Signature Authentication](https://github.com/otrv4/otrv4/blob/master/otrv4.md#ring-signature-authentication)
   section of the OTRv4 specification for details.
4. Use the sender's instance tag from the DAKE-1 message as the receiver's
   instance tag.

To verify an DAKE-2 message:

1. Check that the receiver's instance tag matches your sender's instance tag.
4. Validate the Server's Identifier by:
   * Calculate the fingerprint of the Server's long-term public key (`H_s`).
   * Calculate the Server's Identifier and compare with the one received.
   Extract `H_s` from it.
5. Compute `t = 0x00 || KDF(0x02 || Alices_User_Profile, 64) ||
   KDF(0x03 || Servers_Indentifier, 64) || I || S || KDF(0x04 || phi, 64)`.
   `phi` is the shared session state as mention in its
   [section](#shared-session-state). `Servers_Identifier` is the server's
   identifier as mention in its [section](#servers-identifier).
6. Verify the `sigma` with `sigma == RVrf({H_a, H_s, I}, t)`. See
   [Ring Signature Authentication](https://github.com/otrv4/otrv4/blob/master/otrv4.md#ring-signature-authentication)
   section of the OTRv4 specification for details.

A DAKE-2 message is an OTRv4 Prekey Server message encoded as:

```
Message type (BYTE)
  The message has type 0x02.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

Server's Identifier (PREKEY-SERVER-ID)
  As described in the section "Server's Identifier".

S (POINT)
  The ephemeral public ECDH key.

sigma (RING-SIG)
  The 'RING-SIG' proof of authentication value.
```

### DAKE-3 Message

This is the final message of the DAKE. It is sent to verify the authentication
`sigma`.

A valid DAKE-3 message is generated as follows:

1. Compute
   `t = 0x01 || KDF(0x05 || Alices_User_Profile, 64) ||
    KDF(0x06 || Servers_Identifier, 64) || I || S || KDF(0x07 || phi, 64)`.
   `phi` is the shared session state as mention in its
   [section](#shared-session-state). `Servers_Identifier` is the server's
   identifier as mention in its [section](#servers-identifier).
2. Compute `sigma = RSig(H_a, sk_ha, {H_a, H_s, S}, t)`, as defined in
   [Ring Signature Authentication](https://github.com/otrv4/otrv4/blob/master/otrv4.md#ring-signature-authentication)
   section of the OTRv4 specification.
3. Continue to use the sender's instance tag.

To verify a DAKE-3 message:

1. Check that the receiver's instance tag matches your sender's instance tag.
2. Compute
   `t = 0x01 || KDF(0x05 || Alices_User_Profile, 64) ||
    KDF(0x06 || Servers_Identifier, 64) || I || S || KDF(0x07 || phi, 64)`.
   `phi` is the shared session state as mention in its
   [section](#shared-session-state). `Servers_Identifier` is the server's
   identifier as mention in its [section](#servers-identifier).
3. Verify the `sigma` with `sig == RVrf({H_s, H_a, S}, t)`. See
   [Ring Signature Authentication](https://github.com/otrv4/otrv4/blob/master/otrv4.md#ring-signature-authentication)
   section of the OTRv4 specification for details.

A DAKE-3 is an OTRv4 Prekey Server message encoded as:

```
Message type (BYTE)
  The message has type 0x03.

Sender's instance tag (INT)
  The instance tag of the person sending this message.

sigma (RING-SIG)
  The 'RING-SIG' proof of authentication value.

Message (DATA)
  The message sent to the prekey server.
  In this protocol there are 2 kinds of messages:
    - Prekey publication
    - Storage information
```

### Prekey Publication Message

This is the message sent when you want to store/publish prekey messages to the
Prekey Server. The maximum number of prekey messages that can be published at
one is 255.

A valid Prekey Publication message is generated as follows:

1. Concatenate all the prekey messages. Assign `N` as the number of concatenated
   prekey messages.
2. Calculate the `Prekey MAC`:
   `KDF(0x09 || prekey_mac_k || message type || N || prekey messages, 64)`

It must be encoded as:

```
Message type (BYTE)
  This message has type 0x04.

N (BYTE)
   The number of prekey messages present in this message.

Prekey messages (DATA)
   All 'N' prekey messages serialized according to OTRv4 specification.

Prekey MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the prekey messages.
```

This message MUST immediatelly follow a DAKE-3 message.

### Storage Information Message

This is the message sent when you want to know how many prekey messages are
there in storage. Only the publisher of those prekey messages can send this
message.

It must be encoded as:

```
Message type (BYTE)
  This message has type 0x05.
```

This message MUST immediatelly follow a DAKE-3 message.

### Storage Status Message

The storage status message is sent by the Prekey Server in response to a
Storage information request.

A valid Storage Status message is generated as follows:

1. Calculate the `MAC`:
   `KDF(0x10 || prekey_mac_k || message type || receiver's instance tag || stored prekey messages, 64)`

It must be encoded as:

```
Message type (BYTE)
  The message has type 0x06.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

Stored prekey messages (INT)
  The number of prekey messages stored in the prekey server for the
  long-term public key used during the DAKE.

MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the stored prekey messages.
```

### No Prekey-Messages on Storage Message

This message is sent by the Prekey Server when it runs out of prekey messages
(there are none on storage).

A valid No Prekey-Message on Storage message is generated as follows:

1. Calculate the `MAC`:
   `KDF(0x11 || prekey_mac_k || message type || receiver's instance tag || "No prekey messages available for this identity", 64)`

It must be encoded as:

```
Message type (BYTE)
  The message has type 0x07.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

No Prekey-Messages message (DATA)
  The human-readable details of this message. It contains the string "No prekey
  messages available for this identity".

MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the No Prekey-Messages message.
```

### Success Message

The success message is sent by the Prekey Server when an action (storing a
prekey message, for example) has been successful.

A valid Success message is generated as follows:

1. Calculate the `MAC`:
   `KDF(0x12 || prekey_mac_k || message type || receiver's instance tag || "Success", 64)`

It must be encoded as:

```
Message type (BYTE)
  The message has type 0x08.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

Success message (DATA)
  The human-readable details of this message. It contains the string "Success".

MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the Success message.
```

### Failure Message

The failure message is sent by the Prekey Server when an action (storing a
prekey message, for example) has not been successful. This can happen when the
Prekey Server's storage is full.

It must be encoded as:

```
Message type (BYTE)
  The message has type 0x09.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

Success message (DATA)
  The human-readable details of this message. It contains the string "An error
  occurred".
```

## State machine

This is the state machine for when a client wants to publish prekey messages to
the Prekey Server or query it for status.

Protocol States:

```
IN_DAKE:

  This is the state where a client has sent a DAKE-1 message, or when the Prekey
  Server has sent a DAKE-2 message.

NOT_IN_DAKE:
  This is the state where a client or the Prekey Server are not in the
  'IN_DAKE' state.
```
There are four events an OTRv4 client must handle:

* Starting the DAKE
* Receiving a DAKE-1 message
* Receiving a DAKE-2 message
* Receibing a DAKE-3 message

**Starting the DAKE**

* Client generates and sends a DAKE-1 message.
* Transitions to IN_DAKE.

**Receiving a DAKE-1 message**

* Prekey Server generates and sends a DAKE-2 message.
* Transitions to IN_DAKE state.

**Receiving a DAKE-2 message**

* If client is in state IN_DAKE:

  * Client generates and sends a DAKE-3 message.
  * Transitions to NOT_IN_DAKE state.

* Otherwise:

  * Ignores message.

**Receiving a DAKE-3 message**

* If server is in state IN_DAKE:

  * Transitions to NOT_IN_DAKE state.

* Otherwise:

  * Ignores the message.


## Publishing Prekey Messages

```
Alice has 'sk_a' and Ha' and 'Alices_User_Profile'
The Prekey Server has 'sk_s' and 'Hs' and 'Servers_Identifier'.

Alice                                                Prekey Server
----------------------------------------------------------------------------------------
Sends a DAKE-1 message               ------------->

                                     <-------------  Receives a DAKE-1 message and
                                                     sends a DAKE-2 message

Receives a DAKE-2 message and
sends a DAKE-3 message with a
Prekey publication message           ------------->

                                     <-------------  Receives a DAKE-3 message and
                                                     stores the prekey message.
                                                     Sends a Success message
```

Notice that this section refers to the ideal functionality of a Prekey Server.
Nevertheless, consider that an unstrusted Prekey Server can, for example, not
perform some of the verifications here noted.

1. Client creates prekey messages, as defined in OTRv4 specification. See
   the [Prekey message](#https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-message)
   section of the OTRv4 specification for details.
1. Client receives a Prekey Server's identifier (e.g. prekey.autonomia.digital)
   and the Prekey Server's long-term public key from a source. In XMPP, for
   example, it happens over the server's service discovery.
1. Client authenticates (in a deniable way) with the server through the
   interactive DAKE 'DAKEZ' and, with that, it generates a shared secret.
   See section [Interactive DAKE](#interactive-dake) for details.
1. Client sends prekey messages to the Prekey Server, in the last message of the
   DAKE (DAKE-3 with a Prekey publication message attached). It sends a prekey
   message for every long-term public key that belongs to the publisher and that
   exists in this client/device.
1. Server verifies the received prekey messages. For every prekey message:
   1. Checks the integrity of the prekey message.
   1. Discard any duplicated prekey message.
   1. Checks that the User Profile is not expired.
   1. Checks that the Prekey Profile is not expired.
   1. Checks that the OTR version in the prekey message matches one of the
      versions signed in the User Profile contained in the prekey message.
1. Server stores the prekey messages.
1. Server sends acknowledgment that the operation succeeded.

## Retrieving Prekey Messages

```
Alice has 'sk_a' and Ha' and 'Alices_User_Profile'
The Prekey Server has 'sk_s' and 'Hs' and 'Servers_Identifier'.

Bob                                                  Prekey Server
----------------------------------------------------------------------------------------
Informs Alice's identity             ------------->
(for example, alice@xmpp.org)

                                     <-------------  Sends prekey messages for
                                                     alice@xmpp.org

Receives prekey messages and
verifies them.
```

In order to send an encrypted offline message, a client must obtain a prekey
message from the party they are willing to start a conversation with:

1. Client informs which identity and protocol versions it wants Prekey Messages for.
1. Server checks if there are prekey messages on storage for this identity.
   If there are none, it sends a "No Prekey-Messages on Storage" message.
1. Server selects one prekey message for each instance tag and long-term public
   key for the identity.
   1. For each requested version:
      1. Group all prekey messages that match the version by instance tag,
         and then by long-term public key. That is, only return multiple
         prekey messages for the same instance tag if they have different
         long-term keys.
      1. Filter out expired prekey messages from each group (by checking if the
         User Profile and/or the Prekey Profile are expired).
      1. Choose one prekey message from each group.
1. Server delivers all selected prekey messages to the Client.
1. Server removes the selected prekey messages from its storage.
1. For each requested version, the Client selects prekey messages with the
   latest expiration date form each instance tag and long-term public key
   group:
   1. For each requested version:
      1. Group all prekey messages that match the version by instance tag,
         and then by long-term public key. That is, only return multiple
         prekey messages for the same instance tag if they have different
         long-term keys.
      1. Filter out expired prekey messages from each group (by checking if the
         User Profile and/or the Prekey Profile are expired).
   1. Choose the prekey message with the latest expiry time from the group.
   1. Discards any duplicated prekey message.
   1. Filter out invalid prekey messages from the group, as defined in the
      [Validating Prekey Messages](#https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-prekey-message)
      section of the OTRv4 specification:
      1. Checks that the User Profile is not expired.
      1. Checks that the Prekey Profile is not expired.
      1. Checks that the OTR version of the prekey message matches one of the
         versions signed in the User Profile contained in the prekey message.
      1. Check if the User Profile's version is supported by the receiver.
1. Client chooses which prekey messages to send an encrypted offline message to:
   1. Optionally, a client can only use prekey messages that contain trusted
      long-term public keys.
   1. If there are several instance tags in the list of prekey messages, the
      client can optionally decide which instance tags to send messages to.
      Inform the user if the encrypted messages will be send to multiple
      instance tags (multiple devices).
   1. Decide if multiple conversations should be kept simultaneously (one per
      instance tag).

## Query the server for its storage status

```
Alice has 'sk_a' and Ha' and 'Alices_User_Profile'
The Prekey Server has 'sk_s' and 'Hs' and 'Servers_Identifier'.

Alice                                                Prekey Server
----------------------------------------------------------------------------------------
Sends a DAKE-1 message               ------------->

                                     <-------------  Receives a DAKE-1 message and
                                                     sends a DAKE-2 message

Receives a DAKE-2 message and
sends a DAKE-3 message with a
Storage information request message  ------------->

                                     <-------------  Receives a DAKE-3 message and
                                                     sends a Storage Status message
```

1. Client uses DAKEZ to authenticate with the server. See section
   [Interacive DAKE](#interactive-dake).
2. Server responds with a "Storage Status message" containing the number of
   prekey messages stored for the long-term public key and identity used during
   the DAKEZ.

## A prekey server for OTRv4 over XMPP

This is an example of how a Prekey Server for OTRv4 acts over XMPP. Note that a
Prekey Server's implementation over XMPP must support the Service Discovery
(XEP-0030, "disco").

### Discovering a prekey service

An entity often discovers a prekey service by sending a Service Discovery items
("disco#items") request to its own server.

```
  <iq from='alice@xmpp.org/notebook'
      id='h7ns81g'
      to='xmpp.org'
      type='get'>
    <query xmlns='http://jabber.org/protocol/disco#items'/>
  </iq>
```

The server then returns the services that are associated with it:

```
  <iq from='xmpp.org'
      id='h7ns81g'
      to='alice@xmpp.org/notebook'
      type='result'>
    <query xmlns='http://jabber.org/protocol/disco#items'>
      <item jid='prekey.xmpp.org'
            name='OTRv4 Prekey Server'/>
    </query>
  </iq>
```

### Discovering the features supported by a prekey service

An entity may wish to discover if a service implements the OTRv4 Prekey Server
protocol. In order to do so, it sends a service discovery information
("disco#info") query to the prekey service's JID.

```
  <iq from='alice@xmpp.org/notebook'
      id='lx09df27'
      to='prekey.xmpp.org'
      type='get'>
    <query xmlns='http://jabber.org/protocol/disco#info'/>
  </iq>
```

The service must return its identity and the features it supports:

```
  <iq from='prekey.xmpp.org'
      id='lx09df27'
      to='alice@xmpp.org/notebook'
      type='result'>
    <query xmlns='http://jabber.org/protocol/disco#info'>
      <identity
          category='otrv4-prekey'
          name='OTRv4 Prekey Server'
          type='text'/>
      <feature var='http://jabber.org/protocol/otrv4-prekey'/>
    </query>
  </iq>
```

### Publishing prekeys to the service

An entity authenticates to the service through an interactive DAKE. DAKE
messages are send in "message" stanzas.

An entity starts the DAKE by sending the first encoded message in the body
of a message:

```
  <message
      from='alice@xmpp.org/notebook'
      id='nzd143v8'
      to='prekey.xmpp.org'>
    <body>?OTRPEB...</body>
  </message>
```

The service responds with another message:

```
  <message
      from='prekey.xmpp.org'
      id='13fd16378'
      to='alice@xmpp.org/notebook'>
    <body>?OTRPEC...</body>
  </message>
```

And the entity terminates the DAKE and sends the prekey messages (DAKE-3 message
has action 0x03):

```
  <message
      from='alice@xmpp.org/notebook'
      id='kud87ghduy'
      to='prekey.xmpp.org'>
    <body>?OTRPED...</body>
  </message>
```

And the server responds with a success message:

// TODO: Should this message also have instance tags?

```
  <message
      from='prekey.xmpp.org'
      id='0kdytsmslkd'
      to='alice@xmpp.org/notebook'>
    <body>?OTRP OK</body>
  </message>
```

### Obtaining information about your prekeys from the service

An entity authenticates to the service through a DAKE. DAKE messages are send
in "message" stanzas.

An entity starts the DAKE by sending the first encoded message in the body
of a message.

```
  <message
      from='alice@xmpp.org/notebook'
      id='nzd143v8'
      to='prekey.xmpp.org'>
    <body>?OTRPEB...</body>
  </message>
```

The service responds with another message.

```
  <message
      from='prekey.xmpp.org'
      id='13fd16378'
      to='alice@xmpp.org/notebook'>
    <body>?OTRPEC...</body>
  </message>
```

And the entity terminates the DAKE and asks for storage information (DAKE-3
message has action 0x05):

```
  <message
      from='alice@xmpp.org/notebook'
      id='kud87ghduy'
      to='prekey.xmpp.org'>
    <body>?OTRPED...</body>
  </message>
```

And the server respond with a storage status message:

```
  <message
      from='prekey.xmpp.org'
      id='0kdytsmslkd'
      to='alice@xmpp.org/notebook'>
    <body>?OTRPEE...</body>
  </message>
```

#### Retrieving published prekeys from a prekey service

An entity asks the service for prekey messages from a particular subject,
for example, "bob@xmpp.net". Use the resourcePart of a JID to say which
versions you are interested on, for example "45" if you are interested on
verisons "4" and "5".

```
  <message
      from='alice@xmpp.org/notebook'
      id='nzd143v8'
      to='prekey.xmpp.org'>
    <subject>bob@xmpp.net/45</subject>
  </message>
```

The service responds with a Prekey Publication message, this time not attached
to a DAKE-3 message and without the Prekey MAC field:

```
  <message
      from='prekey.xmpp.org'
      id='13fd16378'
      to='alice@xmpp.org/notebook'>
    <subject>bob@xmpp.net/45</subject>
    <body>?OTRP...</body>
  </message>
```

## Detailed example of the prekey server over XMPP

`bob@xmpp.org` wants to know how many prekeys messages remain unused on the
Prekey Server:

1. bob@xmpp.org logs in to his server (`talk.xmpp.org`).
1. bob@xmpp.org uses service discovery to find a Prekey Server on his server
   (`prekey.xmpp.org`).
   1. The service discovery also informs the Prekey Server's long-term public
      key.
1. `bob@xmpp.org` discovers the capabilities of `prekey.xmpp.org`.
   1. `prekey.xmpp.org` is capable of all features of a Prekey Server.
1. `bob@xmpp.org` asks `prekey.xmpp.org` about the number of prekeys messages
   it has stored for him.
   1. TODO: Explain the DAKE.

`bob@xmpp.org` wants to publish/store prekey messages in the Prekey Server:

1. `bob@xmpp.org` logs to his server (`talk.xmpp.org`).
1. `bob@xmpp.org` uses service discovery to find a Prekey Server on his server
   (`prekey.xmpp.org`).
   1. The service discovery also informs the Prekey Server's long-term public
      key.
1. `bob@xmpp.org` discovers the capabilities of `prekey.xmpp.org`.
   1. `prekey.xmpp.org` is capable of all features of a Prekey Server.
1. bob@xmpp.org generates 3 prekeys:
   1. prekey1: instance tag 90
   1. prekey2: instance tag 90
   1. prekey3: instance tag 90
1. `bob@xmpp.org` sends DAKE-1 to `prekey.xmpp.org`:
   1. TODO: details of how ephemeral keys will be generated.
1. `bob@xmpp.org` receives DAKE-2 from `prekey.xmpp.org/123980831`: (the
   resource identifies this in progress DAKE):
   1. TODO: details of how ephemeral keys will be generated.
   1. `bob@xmpp.org` verifies `prekey.xmpp.org` long-term public key.
1. `bob@xmpp.org` sends DAKE-3 to `prekey.xmpp.org/123980831`:
   1. TODO: details of how to attach prekeys to the DAKE-3.
   1. DAKE-3 also contains prekey1, prekey2, prekey3.
1. `bob@xmpp.org` receives a SUCCESS/FAILURE message from
   `prekey.xmpp.org/123980831`.

`alice@jabber.org` wants to send an offline message to `bob@xmpp.org`:

1. `alice@jabber.org` logs to his server (`xmpp.jabber.org`).
1. `alice@jabber.org` uses service discovery to find a Prekey Server on Bob's
   server (`prekey.xmpp.org`).
   1. The service discovery also informs the Prekey Server's long-term public
      key.
1. `alice@jabber.org` discovers the capabilities of `prekey.xmpp.org`.
   1. `prekey.xmpp.org` is capable of all features of a Prekey Server.
1. `alice@jabber.org` asks `prekey.xmpp.org` for prekeys from `bob@xmpp.org`.
1. `prekey.xmpp.org` delivers 3 prekeys to her:
   1. Server has the following prekey messages stored for `bob@xmpp.org`
      1. prekey1: instance tag 90. Expired.
      1. prekey2: instance tag 90. Not expired.
      1. prekey3: instance tag 91. Not expired.
      1. prekey4: instance tag 91. Not expired.
   1. Server chooses to deliver the following prekey messages to
      `alice@jabber.org`:
      1. prekey2: instance tag 90. Not expired.
      1. prekey3: instance tag 91. Not expired.
1. `alice@jabber.org` choses which prekey messages to use:
   1. Validates the received prekey messages:
      1. Checks that they are not expired.
      1. As the received prekey messages have different instance tags, ther is
         no need to choose by latest expiration time.
   1. Client asks the user if they want to send one message to each instance
      tag:
      1. If the user accepts, sends one message to each instance tag.
      1. If user does not accept, sends one message to the instance tag/device
         chosen by the user.
1. `alice@jabber.org` sends offline encrypted messages to `bob@xmpp.org`.

## Attacks

### KCI attacks and the unstrusted prekey server

The security of Non-Interactive DAKE (XZDH) in OTRv4 specification does not
require trusting the central server used to distribute prekeys messages.
However, if we allow a scenario in which the user’s keys have been compromised
but the central prekey server has not, then we can achieve better plausible
deniability. The user may ask the central server in advance to assist with a
forged conversation, casting doubt on all conversations conducted by the judge
using the compromised device.

## References

1. *OTR version 4*. Available at
   https://github.com/otrv4/otrv4/blob/master/otrv4.md
2. Goldberg, I. and Unger, N. (2016). *Improved Strongly Deniable Authenticated
   Key Exchanges for Secure Messaging*, Waterloo, Canada: University of Waterloo.
   Available at: http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf
3. Hamburg, M. (2015). *Ed448-Goldilocks, a new elliptic curve*, NIST ECC
   workshop. Available at: https://eprint.iacr.org/2015/625.pdf
4. Hamburg, M., Langley, A. and Turner, S. (2016). *Elliptic Curves for
   Security*, Internet Engineering Task Force, RFC 7748. Available at:
   http://www.ietf.org/rfc/rfc7748.txt
