# OTRv4 Prekey Server

```
Disclaimer

This protocol specification is a draft.
```

OTRv4 Prekey Server is an additional specification to the OTRv4
[\[1\]](#references) protocol for when it needs an untrusted central Prekey
Server to store Prekey Ensembles.

## Table of Contents

1. [High Level Overview](#high-level-overview)
1. [Definitions](#definitions)
1. [Assumptions](#assumptions)
1. [Security Properties](#security-properties)
1. [Prekey Server Requirements](#prekey-server-requirements)
1. [Notation and Parameters](#notation-and-parameters)
   1. [Notation](#notation)
   1. [Elliptic Curve Parameters](#elliptic-curve-parameters)
   1. [Key Derivation Functions](#key-derivation-functions)
1. [Data Types](#data-types)
   1. [Encoded Messages](#encoded-messages)
   1. [Public keys and Fingerprints](#public-keys-and-fingerprints)
   1. [Shared Session State](#shared-session-state)
   1. [Prekey Server Composite Identity](#prekey-server-composite-identity)
1. [Key Management](#key-management)
   1. [Shared Secrets](#shared-secrets)
   1. [Generating Shared Secrets](#generating-shared-secrets)
1. [Key Exchange](#key-exchange)
   1. [DAKE-1 Message](#dake-1-message)
   1. [DAKE-2 Message](#dake-2-message)
   1. [DAKE-3 Message](#dake-3-message)
   1. [Prekey Publication Message](#prekey-publication-message)
   1. [Storage Information Request Message](#storage-information-request-message)
   1. [Storage Status Message](#storage-status-message)
   1. [No Prekey Ensembles in Storage Message](#no-prekey-ensembles-in-storage-message)
   1. [Success Message](#success-message)
   1. [Failure Message](#failure-message)
1. [Proofs](#proofs)
   1. [Prekey Profile proof](#proofs-prekey-profile-proof)
   1. [Prekey Messages proofs](#proofs-prekey-messages-proofs)
      1. [ECDH](#proofs-prekey-messages-proofs-ecdh)
      1. [DH](#proofs-prekey-messages-proofs-dh)
1. [State machine](#state-machine)
1. [Publishing Prekey Values](#publishing-prekey-values)
1. [Retrieving Prekey Ensembles](#retrieving-prekey-ensembles)
   1. [Prekey Ensemble Query Retrieval Message](#prekey-ensemble-query-retrieval-message)
   1. [Prekey Ensemble Retrieval Message](#prekey-ensemble-retrieval-message)
   1. [No Prekey Ensembles in Storage Message](#no-prekey-ensembles-in-storage-message)
1. [Query the Prekey Server for its Storage Status](#query-the-prekey-server-for-its-storage-status)
1. [Fragmentation of some Messages](#fragmentation-of-some-messages)
   1. [Transmitting Fragments](#transmitting-fragments)
   1. [Receiving Fragments](#receiving-fragments)
1. [A Prekey Server for OTRv4 over XMPP](#a-prekey-server-for-otrv4-over-xmpp)
   1. [Discovering a Prekey Server](#discovering-a-prekey-server)
   1. [Publishing Prekey Values to the Server](#publishing-prekey-values-to-the-server)
   1. [Obtaining Information about Prekey Messages from the Server](#obtaining-information-about-prekey-messages-from-the-server)
   1. [Retrieving published Prekey Ensembles from a Prekey Server](#retrieving-published-prekey-ensembles-from-a-prekey-server)
1. [Detailed Example of the Prekey Server over XMPP](#detailed-example-of-the-prekey-server-over-xmpp)
1. [References](#references)

## High Level Overview

The OTRv4 Prekey Server specification defines a way by which parties can
publish and store Client Profiles, Prekey Profiles and Prekey Messages, and
retrieve Prekey Ensembles from an untrusted Prekey Server. A Prekey Ensemble
contains the publisher's Client Profile, the publisher's Prekey Profile and one
Prekey Message (which contains one-time use ephemeral public prekey values), as
defined in the OTRv4 specification [\[1\]](#references). These Prekey Ensembles
are used for starting offline conversations.

The OTRv4 specification defines a non-interactive DAKE, which is derived from
the XZDH protocol. This DAKE begins when Alice, who wants to initiate an offline
conversation with Bob, asks an untrusted Prekey Server for a Prekey Ensemble for
Bob. The values for the Prekeys Ensembles have been previously stored in
the Prekey Server by a request from Bob.

This document aims to describe how the untrusted Prekey Server can be used to
securely publish, store and retrieve Prekey Ensembles and its values.

## Definitions

Unless otherwise noted, these conventions and definitions are used for this
document:

* "Network" refers to the system which computing devices use to exchange data
  with each other using connections between nodes.
* "Participant" refers to any of the end-points that take part in a
  conversation.
* "Prekey Server" refers to the untrusted server used to store Prekey
  Ensembles.
* "Publisher" refers to the participant publishing Prekey Ensembles to
  the Prekey Server.
* "Receiver" refers to the participant receiving a message.
* "Retriever" refers to the participant retrieving Prekey Ensembles from
  the Prekey Server that correspond to the publishing participant.
* "Sender" refers to the participant sending a message.

## Assumptions

The OTRv4 Prekey Server specification can not protect against an active
attacker performing Denial of Service attacks (DoS). This means that this
specification does not prevent any attack which will make the Prekey Server or
its functionalities unavailable (by temporarily or indefinitely disrupting the
service).

This specification aims to support future OTR versions. Because of that, the
Prekey Server should support multiple Prekey Messages from different/future
OTR versions, starting with the current version, 4. Each message defined in this
document, will, therefore, advertise which version it is using.

The communication with a party and the Prekey Server is synchronous, which means
that there can only be one request in flight at the same time from the same
party while using an specific device.

The network model provides in-order and out-of-order delivery of messages. Some
messages may not be delivered. Note that with communication with the Prekey
Server, there can only be one request in flight at the same time from the party
communicating with.

## Security Properties

OTRv4 states the need for a service provider that stores key material used in
a deniable trust establishment for offline conversations. This service provider
is the Prekey Server, as established in this specification.

There are three things that should be uploaded to the Prekey Server by each
device: a Client Profile, a Prekey Profile and Prekey Messages. These are needed
for starting a non-interactive DAKE. A Prekey Profile is needed, because if only
Prekey Messages are used for starting non-interactive conversations, an active
adversary can modify the first flow from the publisher to use an adversarially
controlled ephemeral key, capture and drop the response from the retriever,
compromise (by for example, getting access to the publisher's device) the
publisher's long-term secret key, and then be able to decrypt messages. The
publisher will never see the messages, and the adversary will be able to decrypt
them.  Moreover, since long-term keys are usually meant to last for years, a
long time may pass between the retriever sending messages and the adversary
compromising the publisher's long-term key. This attack is mitigated with the
use of a Prekey Profile that contain shared prekeys signed by the long-term
secret key, and that are reusable, as defined by Unger et al
[\[2\]](#references).

A Prekey Server can also be used to publish the Client Profile, even if OTRv4 is
implemented in the OTRv4-interactive-only mode. This should be done in order to
achieve deniability properties, as it allows two parties to send and verify each
other's Client Profile during the DAKEs without damaging participation
deniability for the conversation, since the Client Profile becomes public
information. However, if the network model does not support any kind of central
infrastructure another place can be used to publish, like a server pool (similar
to a keyserver pool, where PGP public keys can be published).

The submissions of these values to the untrusted Prekey Server are deniably
authenticated by using DAKEZ. If they were not authenticated, malicious
users could perform denial-of-service attacks. In order to preserve the
deniability properties of the whole OTRv4 protocol, they should be deniably
authenticated.

Furthermore, in order to safeguard the integrity of the submitted values to the
Prekey Server, a MAC of the sent values is used. The Prekey Server should
validate this MAC after receiving the values.

Finally, all public key values will be submitted together with a zero-knowledge
proof of knowledge that shows the publisher controls the private keys
corresponding to those values.

Note that the Prekey Server is untrusted and therefore can cause the
communication between two parties to fail. This can happen in several ways:

- The Prekey Server is unavailable.
- The Prekey Server refuses to hand out Prekey Ensembles.
- The Prekey Server hands out incomplete Prekey Ensembles.
- The Prekey Server hands out expired Prekey Ensembles.
- The Prekey Server hands out Prekey Messages that have been already used.
- The Prekey Server reports incorrect number of stored Prekey Messages.

Additionally, a malicious party can cause DoS attacks to the Prekey Server by:

- Asking for Prekey Ensembles or its contents until the Prekey Server runs out
  of them.
- Send too many requests for Prekey Ensembles or its contents at the same time,
  causing the Preker Server to be overwhelmed.
- Create a extremely big Client Profile and submit it, causing the Prekey Server
  to run out of storage or to crash. (A production level implementation of a
  prekey server should limit the size of publications to reasonable sizes.)

## Prekey Server Requirements

The Prekey Server used in this specification should be considered untrusted.
This means that a malicious server could cause communication between parties to
fail, as stated above.

The Prekey Server must have these capabilities:

- Receive a Client Profile, a Prekey Profile and a set of Prekey Messages, and
  store them by the corresponding identity. Inform that this operation have
  failed or has been successful.
- Deliver Prekey Ensembles previously stored.
- Inform the publisher about how many Prekey Messages are stored for them.
- Inform the retriever when there are no complete Prekey Ensembles available
  for a specific participant.

The Prekey Server expects to only receive messages on the same network that
authenticated clients use to exchange messages. This means that a message
received should be from the same network the publisher is believed to have been
authenticated with.

Although this specification defines expected behavior from the Prekey Server
(e.g., by specifying that the Client Profile, the Prekey Profile and Prekey
Messages submissions should be validated by the Prekey Server), clients should
not rely on this prescribed behavior, as the Prekey Server is untrusted.
Verifications must be performed by clients as well, even though the Prekey
Server should be expected to perform them. Clients working with a Prekey Server
are expected to upload a new Client Profile and a new Prekey Profile before they
expire, when a new long-term public key has been created or when a value in
them has changed.

Note that the Client Profile, the Prekey Profile and Prekey Messages submissions
to the untrusted Prekey Server have to be authenticated. If they are not
authenticated, then malicious users can perform denial-of-service attacks. To
preserve the deniability of the overall OTRv4 protocol, Prekey Ensembles should
never be signed in a non-repudiable way. This specification uses a DAKEZ
exchange between the publisher and the Prekey Server to fulfill this need, and
preserve deniability. In addition, a zero-knowledge proof of knowledge is also
used to demonstrate knowledge of the secrets associated with the individual
public values.

In order to correctly perform the DAKEZ with the publisher, the untrusted Prekey
Server should be able to correctly generate ephemeral ECDH keys and long-term
Ed488-EdDSA keys.

When the Prekey Server runs out of Prekey Messages, or when it has no Client or
Prekey Profiles, a "No Prekey Ensembles in Storage" message should be returned,
as defined in this [section](#no-prekey-ensembles-in-storage-message). In
theory, it would be possible to return a "multi use" default Prekey Ensemble.
However, the consequences to participation deniability with this technique are
currently undefined and thus risky. For this reason, this specification does not
use that kind of fallback behavior. As a consequence, the OTRv4 protocol can be
subject to DoS attacks by an attacker draining the Prekey Ensembles for another
user. This can be partially mitigated using fetch rate limiting.

Notice that the Prekey Server should be able to support future versions,
starting from version 4. This means that the Prekey Server will accept Prekey
Ensembles with different versions. For this reason, the header of a Prekey
Message must remain the same in future versions:

```
Protocol version (SHORT)
  The version number of the protocol, e.g, 0x0004 for OTRv4.

Message type (BYTE)
  The message type, e.g., 0x36 for the DAKE-2 message.

Prekey Message Identifier (INT)
  A prekey message id used for local storage and retrieval.

Prekey owner instance tag (INT)
  The instance tag of the client that created the Prekey Message.
```

## Notation and Parameters

### Notation

The OTRv4 Prekey Server specification uses the same notation as the OTRv4
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

### Diffie-Hellman Parameters

The OTRv4 Prekey Server specification uses the same Diffie-Hellman parameters as
defined in [3072-bit Diffie-Hellman
Parameters](https://github.com/otrv4/otrv4/blob/master/otrv4.md#3072-bit-diffie-hellman-parameters). These
values are used to verify the proofs submitted for Diffie-Hellman values in the
Prekey Messages submitted.

### Key Derivation Functions

The following key derivation function is used in this specification. The usageID
is of type BYTE:

```
  KDF(usage_ID, values, size) = SHAKE-256("OTR-Prekey-Server" || usageID || values, size)
```

The `size` first bytes of the SHAKE-256 output for the input
`"OTR-Prekey-Server" || usageID || values` will be returned.

Unlike in the SHAKE standard, the output size (`size`) here is in bytes.

The following `usageID` variables are defined:

```
  * usage_Fingerprint = 0x00
  * usage_SK = 0x01
  * usage_initiator_client_profile = 0x02
  * usage_initiator_prekey_composite_identity = 0x03
  * usage_initiator_prekey_composite_PHI = 0x04
  * usage_receiver_client_profile = 0x05
  * usage_receiver_prekey_composite_identity = 0x06
  * usage_receiver_prekey_composite_PHI = 0x07
  * usage_preMAC_key = 0x08
  * usage_preMAC = 0x09
  * usage_storage_info_MAC = 0x0A
  * usage_status_MAC = 0x0B
  * usage_success_MAC = 0x0C
  * usage_failure_MAC = 0x0D
  * usage_prekey_message = 0x0E
  * usage_client_profile = 0x0F
  * usage_prekey_profile = 0x10
  * usage_auth = 0x11
  * usage_proof_context = 0x12
  * usage_proof_message_ecdh = 0x13
  * usage_proof_message_dh = 0x14
  * usage_proof_shared_ecdh = 0x15
  * usage_mac_proofs = 0x16
  * usage_proof_c_lambda = 0x12
```

## Data Types

The OTRv4 Prekey Server Specification uses many of the data types already
specified in the OTRv4 specification, as defined in section
[Data Types](https://github.com/otrv4/otrv4/blob/master/otrv4.md#data-types)

The OTRv4 Prekey Server Specification also uses the Prekey Server Composite
Identity data type, which is detailed in the
[Prekey Server Composite Identity](#prekey-server-composite-identity) section.

Note that variable length fields are encoded as DATA. Every string will be
encoded in UTF-8.

Finally, the OTRv4 Prekey Server Specification adds two new data types for proofs:

```
ECDH Proof (PROOF-ECDH):
  C
    64 bytes
   
  V (SCALAR)
```

```
DH Proof (PROOF-DH):
  C
    64 bytes
   
  V (MPI)
```

### Encoded Messages

OTRv4 Prekey Server messages must be base-64 encoded. To transmit one of these
messages, construct an ASCII string of the base-64 encoding of the binary form
of the message and, after this encoding, add the byte ".".

### Public keys and Fingerprints

OTR users have long-lived public keys that they use for authentication (but not
for encryption). The Prekey Server has one as well. It is generated
as defined in the
[Public keys, Shared Prekeys and Fingerprints](https://github.com/otrv4/otrv4/blob/master/otrv4.md#public-keys-shared-prekeys-and-fingerprints)
section of the OTRv4 specification. It has the same Pubkey type. It is denoted
as 'Ed448 server public key'.

Public keys have fingerprints, which are hex strings that serve as identifiers
for the public key. The full OTRv4 fingerprint is calculated by taking the
SHAKE-256 hash of the byte-level representation of the public key. The long-term
public keys for the Prekey Server have fingerprints as well. Note that for its
generation, the same KDF of the OTRv4 specification is used (`
KDF_1(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size)`.
The fingerprint is generated as:

* `KDF_1(usage_fingerprint, byte(H), 56)` (224-bit security level), where `H` is
  the Prekey Server's long-term public key.

### Shared Session State

A Shared Session State between the Prekey Server and the publisher is needed for
the same reasons as stated in the
[Shared Session State](https://github.com/otrv4/otrv4/blob/master/otrv4.md#shared-session-state)
section of the OTRv4 specification. It is used to authenticate contexts to
prevent attacks that rebind the DAKE transcript into different contexts.

Note that variable length fields are encoded as DATA. If `phi` is a string, it
will be encoded in UTF-8.

To make sure both participants has the same phi during DAKE, sort the instance
tags by numerical order and any string passed to `phi` lexicographically.

As an example, for a Prekey Server running over XMPP, this should be:

```
  phi = DATA(publisher's bare JID) || DATA(Prekey Servers's bare JID)
```

For example:

```
  phi = DATA("alice@jabber.net") || DATA("prekey.xmpp.org")
```

### Prekey Server Composite Identity

For the DAKE performed by a publisher and the Prekey Server, an identifier is
needed. This value will be denoted the "Prekey Server Identifier".

This value is the Prekey Server identity concatenated with the Prekey Server
long-term public key.

```
Prekey Server Composite Identity (PREKEY-SERVER-COMP-ID):
  Prekey Server Identity (DATA)
  Ed448 public key (ED448-PUBKEY)
```

For a Prekey Server that uses XMPP, this must be the bare JID of the Prekey
Server (for example, prekey.xmpp.org) and the encoding of its long-term
public key:

```
  Prekey Server Composite Identity = DATA("prekey.xmpp.org") || ENCODE(Ed448 server public key)
```

## Key Management

In the DAKE between the publisher and the Prekey Server, long-term Ed448 keys
and ephemeral Elliptic Curve Diffie-Hellman (ECDH) keys are used.  Notice that
if this DAKE is only used for deniable authentication, the shared secret derived
during the DAKE should be discarded. This shared secret can be used with the
Double Ratchet Algorithm, for example, to either encrypt the channel or by the
Prekey Server to encrypt the stored prekey messages (note that the Prekey Server
must hand them out decrypted to the retrieving participant).

### Shared Secrets

```
  SK_ecdh:
    The serialized ECDH shared secret computed from an ECDH exchange, serialized
    as a 'POINT', as defined in "Encoding and Decoding" section of the OTRv4
    protocol.
  SK:
    The Shared secret is the shared secret derived from the ECDH shared secret:
    'KDF(usage_SK, SK_ecdh, 64)'.
```

### Generating Shared Secrets

```
  ECDH(a, B)
    B = B * cofactor
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
participant's private key. This situation can be detected by checking for the
all-zero output.

## Key Exchange

As previously stated, Client Profiles Prekey Profiles and Prekey Messages
submissions to the Prekey Server have to be authenticated. If they are not
authenticated, malicious users can perform denial-of-service attacks. To
preserve the deniability of the overall OTRv4 protocol, the submissions are
authenticated using a DAKEZ [\[3\]](#references) exchange between the publisher
and the Prekey Server, which preserves deniability.

The following parameters are expected to have been generated:

* `(sk_a, Ha)`: Alice's long-term keypair. As defined in section
   [Public keys, Shared Prekeys and Fingerprints](https://github.com/otrv4/otrv4/blob/master/otrv4.md#public-keys-shared-prekeys-and-fingerprints)
   of the OTRv4 protocol.
* `(sk_s, Hs)`: Ed448 Server's long-term keypair. As defined in section
   [Public keys, Shared Prekeys and Fingerprints](https://github.com/otrv4/otrv4/blob/master/otrv4.md#public-keys-shared-prekeys-and-fingerprints)
   of the OTRv4 protocol.
* `Alices_Client_Profile`: Alice's Client Profile. As defined in section
   [Creating a Client Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#creating-a-client-profile)
   of the OTRv4 protocol.
* `Prekey_Server_Composite_Identity`: the Prekey Server Composite Identity.

Alice is also expected to have the Prekey Server Composite Identity, so that
they can be manually verified by her.

Alice will be initiating the DAKEZ with the Prekey Server:

**Alice**

1. Generates a DAKE-1 message, as defined in the [DAKE-1 Message](#dake-1-message)
   section.
1. Sends the DAKE-1 message to the Prekey Server.

**Prekey Server**

1. Receives the DAKE-1 message from Alice:
    * Verifies the DAKE-1 message as defined in the
      [DAKE-1 message](#dake-1-message) section. If the verification fails
      (for example, if Alice's public key -`I`- is not valid), rejects
      the message and does not send anything further.
1. Stores the `sender instance tag` from the message as the
   `receiver instance tag`.
1. Generates a DAKE-2 message, as defined in
   [DAKE-2 Message](#dake-2-message) section.
1. Calculates the Shared secret (`SK`):
   * `SK_ecdh = ECDH(s, I)`.
   * `SK = KDF(usage_SK, SK_ecdh, 64)`.
   * Securely erases `s`.
1. Sends Alice the DAKE-2 message.

**Alice**

1. Receives the DAKE-2 message from the Prekey Server.
1. Checks that the receiver instance tag from the message matches their
   instance tag. If it is not, rejects the message and does not send anything
   further.
1. Retrieves the ephemeral public keys for the Prekey Server (encoded in the
   DAKE-2 message):
    * Validates that the received ECDH ephemeral public key `S` is on curve
      Ed448, as defined in the
      [Verifying that a point is on the curve](#https://github.com/otrv4/otrv4/blob/master/otrv4.md#verifying-that-a-point-is-on-the-curve)
      section of the OTRv4 protocol. If the verification fails, she rejects the
      message and does not send anything further.
1. Verifies the DAKE-2 message as defined in the
   [DAKE-2 message](#dake-2-message) section. If the verification fails, rejects
   the message and does not send anything further.
1. Creates a DAKE-3 message (see [DAKE-3 Message](#dake-3-message) section).
1. Calculates the Shared secret (`SK`):
   * `SK_ecdh = ECDH(i, S)`.
   * `SK = KDF(usage_SK, SK_ecdh, 64)`.
   * Securely erases `i`.
1. Calculates the Prekey MAC key: `prekey_mac_k = KDF(usage_preMAC_key, SK, 64)`.
1. Creates a message (`msg`):
   1. If she wants to publish a Client Profile, a Prekey Profile, and/or Prekey
      Messages, she creates a "Prekey Publication message", as defined in
      [Prekey Publication Message](#prekey-publication-message) section.
   1. If she wants to ask for storage information, she creates a "Storage
      Information Request message", as defined in the
      [Storage Information Request Message](#storage-information-request-message)
      section.
1. Attaches the corresponding `msg` to the DAKE-3 message, and sends it.

**Prekey Server**

1. Receives the DAKE-3 message from Alice:
   * Checks that the sender instance tag from the message matches the already
     stored `receiver instance tag`. If it is not, rejects the message and does
     not send anything further.
   * Verifies the DAKE-3 message as defined in the
     [DAKE-3 message](#dake-3-message) section. If something fails, the Prekey
     Server rejects the message and does not send anything further.
1. Retrieves the `msg` attached to the DAKE-3 message:
   1. Verifies that the message type is either `0x08` or `0x09`. Aborts if it is
      not.
   1. Verifies that the protocol version of the message is `0x0004` or a higher
      version of the protocol. Aborts if it is not.
   1. If this is a "Prekey Publication message":
      * Calculates the Prekey MAC key:
        `prekey_mac_k = KDF(usage_preMAC_key, SK, 64)`.
      * Computes the `Prekey MAC` (notice that most of these values are from the
        received "Prekey Publication message"):
        * If a Client Profile and Prekey Profile are present in the message:
          `KDF(usage_preMAC, prekey_mac_k || message type || N ||
           KDF(usage_prekey_message, Prekey Messages, 64) || K ||
           KDF(usage_client_profile, Client Profile, 64) || J ||
           KDF(usage_prekey_profile, Prekey Profile, 64) || Q ||
           KDF(usage_mac_proofs, Proofs, 64))`.
        * If only Prekey Messages are present in the message:
          * Calculate `KDF(usage_PreMAC, prekey_mac_k || message type || N ||
            KDF(usage_prekey_message, Prekey Messages, 64) || K || J || Q ||
           KDF(usage_mac_proofs, Proofs, 64)), 64)`. `J`
            and `K` should be set to zero.
        * Checks that this `Prekey MAC` is equal to the one received in the
          "Prekey publication message". If it is not, the Prekey Server aborts
          the DAKE and sends a "Failure message", as defined in the
          [Failure Message](#failure-message) section.
      * Check the counters for the values on the message:
        * If a Client Profile is present in the message:
          * Checks that `K` is set to 1. If it is not, aborts the DAKE and sends
            a "Failure message", as defined in the [Failure Message](#failure-message)
            section.
        * If a Prekey Profile is present in the message:
          * Checks that `J` is set to 1. If it is not, aborts the DAKE and sends
            a "Failure message", as defined in the [Failure Message](#failure-message)
            section.
        * If Prekey Messages are present in the message:
          * Checks that `N` corresponds to the number of concatenated Prekey
            Messages. If it is not, aborts the DAKE and sends a
            "Failure message", as defined in the
            [Failure Message](#failure-message) section.
          * Checks that `J` and `K` are set to zero, if Prekey Messages are only
            present.
      * Checks that the proofs are valid for all public values submitted for publication.
          * If they are not, If it is not, the DAKE and sends
            a "Failure message", as defined in the [Failure Message](#failure-message)
            section.
      * Stores the Client Profile, the Prekey Profile and Prekey Messages, if is
        possible, in the Prekey Server's storage. If not, aborts the DAKE and
        sends a "Failure message" as defined in the
        [Failure Message](#failure-message) section.
      * Sends a "Success message", as defined in the
        [Success Message](#success-message) section.
   1. If this is a "Storage Information Request message":
      * Calculates the Prekey MAC key:
        `prekey_mac_k = KDF(usage_preMAC_Key, SK, 64)`.
      * Computes the `Prekey MAC`:
        `KDF(usage_storage_info_MAC, prekey_mac_k || message type, 64)`
      * Checks that this `Prekey MAC` is equal to the one received in the
        "Storage Information Request message". If it is not, the Prekey Server
        aborts the DAKE and sends a "Failure message", as defined in
        the [Failure Message](#failure-message) section.
      * Responds with a "Storage Status message", as defined in
        the [Storage Status Message](#storage-status-message) section.

**Alice**

1. Receives a message from the Prekey Server:
   1. Verifies that the message type is either `0x0B`, `0x06` or `0x05`. Aborts
      if it is not.
   1. Verifies that the protocol version of the message is `0x0004` or a higher
      version of the protocol. Aborts if it is not.
   1. If this is a "Storage Status message":
      * Computes the `Status_MAC: KDF(usage_status_MAC, prekey_mac_k ||
        message type || receiver instance tag ||
        stored prekey messages number, 64)`. Checks
        that it is equal to the one received in the "Storage Status message".
        * If it is not, ignores the message.
        * If it is, the number of stored prekey messages is displayed.
      * Securely deletes `prekey_mac_k`.
   1. If this is a "Success message":
      * Computes the `Success_MAC: KDF(usage_success_MAC, prekey_mac_k ||
        message type || receiver instance tag, 64)`. Checks that
        it is equal to the one received in the "Sucess message".
        * If it is not, ignores the message.
      * Securely deletes `prekey_mac_k`.
   1. If this is a "Failure message":
      * Computes the `Failure_MAC: KDF(usage_failure_MAC, prekey_mac_k ||
        message type || receiver instance tag, 64)`.
        Checks that it is equal to the one received in the "Failure message".
        * If it is not, ignores the message.
      * Securely deletes `prekey_mac_k`.

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
1. Generate a 4-byte instance tag to use as the sender instance tag. Only
   generate it if it hasn't been generated for the OTR part of the
   implementation. If it has, use that one instead. If it hasn't, generate it,
   and use it for the OTR implementation as well. Additional messages in this
   conversation will continue to use this tag as the sender instance
   tag. Also, this tag is used to filter future received messages. Messages
   intended for this instance of the client will have this number as the
   receiver instance tag.
1. Add the Client Profile previously generated.

To verify a DAKE-1 message:

1. Verify that the message type is `0x35`.
1. Verify that the protocol version of the message is `0x0004` or a higher
   version of the protocol. Abort if it is not.
1. Validate the Client Profile, as defined in
   [Validating a Client Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-client-profile)
   section of the OTRv4 specification.
1. Verify that the point `I` received is on curve Ed448. See
   [Verifying that a point is on the curve](https://github.com/otrv4/otrv4/blob/master/otrv4.md#verifying-that-a-point-is-on-the-curve)
   section of the OTRv4 specification for details.

A DAKE-1 message is an OTRv4 Prekey Server message encoded as:

```
Protocol version (SHORT)
  The version number of this OTR protocol is 0x0004.

Message type (BYTE)
  The message has type 0x35.

Sender instance tag (INT)
  The instance tag of the client sending this message.

Sender Client Profile (CLIENT-PROF)
  As described in the section "Creating a Client Profile" of the OTRv4
  specification.

I (POINT)
  The ephemeral public ECDH key.
```

### DAKE-2 Message

This is the second message of the DAKEZ. It is sent to commit to a choice of an
ECDH ephemeral key for the Prekey Server, and to acknowledge the publisher's
ECDH ephemeral key. Before this acknowledgment, validation of the publisher's
ECDH key is done.

A valid DAKE-2 message is generated as follows:

1. Generate an ephemeral ECDH key pair, as defined in the
   [Generating ECDH and DH keys](https://github.com/otrv4/otrv4/blob/master/otrv4.md#generating-ecdh-and-dh-keys)
   section of the OTRv4 specification (ignore the generation of DH keys from
   this section):
   * secret key `s` (57 bytes).
   * public key `S`.
1. Compute
   `t = 0x00 || KDF(usage_initiator_client_profile, Alices_Client_Profile, 64) ||
    KDF(usage_initiator_prekey_composite_identity,
    Prekey_Server_Composite_Indentity, 64) || I || S ||
    KDF(usage_initiator_prekey_composite_PHI, phi, 64)`.
   `phi` is the shared session state as mentioned in the
   [Shared Session State](#shared-session-state) section.
   `Prekey_Server_Composite_Identity` is the Prekey Server Composite Identity
   as mentioned in the
   [Prekey Server Composite Identity](#prekey-server-composite-identity) section.
1. Compute `sigma = RSig(H_s, sk_hs, {H_a, H_s, I}, t)`. See the
   [Ring Signature Authentication](https://github.com/otrv4/otrv4/blob/master/otrv4.md#ring-signature-authentication)
   section of the OTRv4 specification for details. Notice that this
   specification will use the KDF stated in the
   [Key Derivation Functions](#key-derivation-functions) section and for the
   computation of `c`, it will use the `usage_auth` defined in this
   specification.
1. Use the sender instance tag from the DAKE-1 message as the receiver
   instance tag.

To verify a DAKE-2 message:

1. Verify that the message type is `0x36`.
1. Verify that the protocol version of the message is `0x0004` or a higher
   version of the protocol. Abort if it is not.
1. Validate the Prekey Server Composite Identity by:
   * Calculating the fingerprint of the Prekey Server's long-term public key
     (`H_s`) provided in the Composite Identity. This fingerprint can be
     compared against stored data or other measures.
   * Ensure the identity element of the Prekey Server Composite Identity is
     correct.
1. Compute
   `t = 0x00 || KDF(usage_Initiator_Client_Profile, Alices_Client_Profile, 64) ||
   KDF(usage_initiator_prekey_composite_identity,
   Prekey_Server_Composite_Identity, 64) || I || S ||
   KDF(usage_initiator_prekey_composite_PHI, phi, 64)`.
   `phi` is the shared session state from the
   [Shared Session State](#shared-session-state) section.
   `Prekey_Server_Composite_Identity` is the Prekey Server Composite Identity
   from the
   [Prekey Server Composite Identity](#prekey-server-composite-identity)
   section.
1. Verify the `sigma`: `RVrf({H_a, H_s, I}, sigma, t)` See the
   [Ring Signature Authentication](https://github.com/otrv4/otrv4/blob/master/otrv4.md#ring-signature-authentication)
   section of the OTRv4 specification for details.

A DAKE-2 message is an OTRv4 Prekey Server message encoded as:

```
Protocol version (SHORT)
  The version number of this OTR protocol is 0x0004.

Message type (BYTE)
  The message has type 0x36.

Receiver instance tag (INT)
  The instance tag of the intended recipient.

Prekey Server Composite Identity (PREKEY-SERVER-COMP-ID)
  As described in the section "Prekey Server Composite Identity".

S (POINT)
  The ephemeral public ECDH key.

sigma (RING-SIG)
  The 'RING-SIG' proof of authentication value.
```

### DAKE-3 Message

This is the final message of the DAKE. It is sent to verify the authentication
of `sigma`.

A valid DAKE-3 message is generated as follows:

1. Compute
   `t = 0x01 || KDF(usage_receiver_client_profile, Alices_Client_Profile, 64) ||
    KDF(usage_receiver_prekey_composite_identity,
    Prekey_Server_Composite_Identity, 64) || I || S ||
    KDF(usage_receiver_prekey_composite_PHI, phi, 64)`.
   `phi` is the shared session state from
   [Shared Session State](#shared-session-state).
   `Prekey_Server_Composite_Identity` is the Prekey Server Composite Identity
   from the
   [Prekey Server Composite Identity](#prekey-server-composite-identity)
   section.
1. Compute `sigma = RSig(H_a, sk_ha, {H_a, H_s, S}, t)`, as defined in the
   [Ring Signature Authentication](https://github.com/otrv4/otrv4/blob/master/otrv4.md#ring-signature-authentication)
   section of the OTRv4 specification. Notice that this
   specification will use the KDF stated in the
   [Key Derivation Functions](#key-derivation-functions) section and for the
   computation of `c`, it will use the `usage_auth` defined in this specification.
1. Continue to use the sender instance tag.

To verify a DAKE-3 message:

1. Verify that the message type is `0x37`.
1. Verify that the protocol version of the message is `0x0004` or a higher
   version of the protocol. Abort if it is not.
1. Check that the receiver instance tag of the message matches their sender
   instance tag.
1. Compute
   `t = 0x01 || KDF(usage_receiver_client_profile, Alices_Client_Profile, 64) ||
    KDF(usage_receiver_prekey_composite_identity,
    Prekey_Server_Composite_Identity, 64) || I || S ||
    KDF(usage_receiver_prekey_composite_PHI, phi, 64)`.
   `phi` is the shared session state from
   [Shared Session State](#shared-session-state).
   `Prekey_Server_Composite_Identity` is the Prekey Server Composite Identity
   from the
   [Prekey Server Composite Identity](#prekey-server-identifier) section.
1. Verify the `sigma`: `RVrf({H_a, H_s, S}, sigma, t)`. See the
   [Ring Signature Authentication](https://github.com/otrv4/otrv4/blob/master/otrv4.md#ring-signature-authentication)
   section of the OTRv4 specification for details.

A DAKE-3 is an OTRv4 Prekey Server message encoded as:

```
Protocol version (SHORT)
  The version number of this OTR protocol is 0x0004.

Message type (BYTE)
  The message has type 0x37.

Sender instance tag (INT)
  The instance tag of the person sending this message.

sigma (RING-SIG)
  The 'RING-SIG' proof of authentication value.

Message (DATA)
  The message sent to the Prekey Server.
  In this protocol there are 2 kinds of messages that can be sent:
    - Prekey Publication
    - Storage Information Request
```

### Prekey Publication Message

This is the message sent when you want to store/publish Prekey Ensembles to the
Prekey Server. This message can contain these three entities:

- Client Profile
- Prekey Profile
- Prekey Messages

It will also contain proofs of the public key values submitted in the Prekey
Profile and the Prekey Messages.

Client Profile and Prekey Profile are included in this message when none have
been published before to the Prekey Server (this is the first time a client
uploads these values), when a new Client or Prekey Profile is generated with a
different long-term public key or other values, and when the stored Client or
Prekey Profile will soon expire. A client must always upload new Client and
Prekey Profiles (at the same time, if the long-term public key changed) when one
of these scenarios happen, to replace the old stored ones. Only one Client
Profile can be published in the message. Only one Prekey Profile can be
published in the message.

Prekey Messages are included in this message when there are few or none of
these messages left on the Prekey Server. This can be checked by sending a
"Storage Status message" to the Prekey Server. If the result of the "Storage
Status message" indicates that the number of stored Prekey Messages is getting
low, the client should upload more Prekey Messages - otherwise it will be
impossible for other clients to start the non-interactive DAKE with the
client. The maximum number of Prekey Messages that can be published in one
message is 255. All Prekey Messages included in the Prekey Publication message
must have the same instance tag. They must also have the same instance
tag as the one stated in the Client and Prekey profiles, if included.

This message must be attached to a DAKE-3 message.

A valid Prekey Publication Message is generated as follows:

1. Calculate the proofs necessary for the values that will be published. There
   will be 0, 2 or 3 proofs, depending on whether there are any prekey messages,
   or any prekey profiles to be published. The generation of proofs is detailed
   in the [Proofs](#proofs) section.
1. Concatenate all the Prekey Messages. Assign `N` as the number of Prekey
   Messages.
1. Concatenate the Client Profile, if it needs to be published. Assign `K`
   to 0x01. If there is no Client Profile, assign 0x00 to `K`.
1. Concatenate the Prekey Profile, if it needs to be published. Assign `J`
   to 0x01. If there is no Prekey Profile, assign 0x00 to `J`.
1. Calculate the `Prekey MAC`:
   * If only a Client Profile is present:
     `KDF(usage_preMAC, prekey_mac_k || message type || N ||
      KDF(usage_prekey_message, Prekey Messages, 64) || K ||
      KDF(usage_client_profile, Client Profile, 64)  || J || 
           KDF(usage_mac_proofs, Proofs, 64), 64)`.
   * If only a Prekey Profile is present:
     `KDF(usage_preMAC, prekey_mac_k || message type || N ||
      KDF(usage_prekey_message, Prekey Messages, 64) || K || J ||
      KDF(usage_prekey_profile, Prekey Profile, 64)  || 
           KDF(usage_mac_proofs, Proofs, 64), 64)`.
   * If a Prekey Profile and a Client Profile are present:
     `KDF(usage_preMAC, prekey_mac_k || message type || N ||
      KDF(usage_prekey_message, Prekey Messages, 64) || K ||
      KDF(usage_client_profile, Client Profile, 64)  || J ||
      KDF(usage_prekey_profile, Prekey Profile, 64)  || 
           KDF(usage_mac_proofs, Proofs, 64), 64)`.
   * If only Prekey Messages are present:
     `KDF(usage_preMAC, prekey_mac_k || message type || N ||
      KDF(usage_prekey_message, Prekey Messages, 64) ||
      K || J, 64) || KDF(usage_mac_proofs, Proofs, 64)`. 
      `K` and `J` should be set to zero.

To verify a Prekey Publication message:

1. Verify that the message type is `0x08`.
1. Verify that the protocol version of the message is `0x0004` or a higher
   version of the protocol. Abort if it is not.
1. Verify that there are `N` number of Prekey messages.
1. Verify that:
   * If there is a Client Profile, that `K` is assign to 0x01.
   * If there is a Prekey Profile, that `J` is assign to 0x01.
   * Otherwise, that they are assigned to 0x00.
1. Calculate the `Prekey MAC`:
   * If only a Client Profile is present:
     `KDF(usage_preMAC, prekey_mac_k || message type || N ||
      KDF(usage_prekey_message, Prekey Messages, 64) || K ||
      KDF(usage_client_profile, Client Profile, 64)  || J || 
           KDF(usage_mac_proofs, Proofs, 64), 64)`.
   * If only a Prekey Profile is present:
     `KDF(usage_preMAC, prekey_mac_k || message type || N ||
      KDF(usage_prekey_message, Prekey Messages, 64) || K || J ||
      KDF(usage_prekey_profile, Prekey Profile, 64) || 
           KDF(usage_mac_proofs, Proofs, 64), 64)`.
   * If a Client Profile and a Prekey Profile are present:
     `KDF(usage_preMAC, prekey_mac_k || message type || N ||
      KDF(usage_prekey_message, Prekey Messages, 64) || K ||
      KDF(usage_client_profile, Client Profile, 64) || J ||
      KDF(usage_prekey_profile, Prekey Profile, 64) || 
           KDF(usage_mac_proofs, Proofs, 64), 64)`.
   * If only Prekey Messages are present:
     `KDF(usage_preMAC, prekey_mac_k || message type || N ||
      KDF(usage_prekey_message, Prekey Messages, 64) ||
      K || J ||  KDF(usage_mac_proofs, Proofs, 64), 64)`. 
      `K` and `J` should be set to zero.
1. Verify that this calculated `Prekey MAC` is equal to the received one. Abort
   if it is not.
1. Verify that all proofs are valid for the values submitted. Verification
   of proofs is detailed in the [Proofs](#proofs) section.

The encoding looks like this:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  This message has type 0x08.

N (BYTE)
   The number of Prekey Messages present in this message.

Prekey Messages
   All 'N' Prekey Messages encoded according to OTRv4 specification.

K (BYTE)
   A number that shows if a Client Profile is present or not. If present, set it
   to one; otherwise, to zero.

Client Profile (CLIENT-PROF)
  The Client Profile created as described in the section "Creating a Client
  Profile" of the OTRv4 specification. This value is optional.

J (BYTE)
  A number that shows if a Prekey Profile is present or not. If present, set it
  to one; otherwise, to zero.

Prekey Profile (PREKEY-PROF)
  The Prekey Profile created as described in the section "Creating a Prekey
  Profile" of the OTRv4 specification. This value is optional.

Proofs (PREKEY-PROOF)
  All proofs indicating the validity of the values submitted. The proofs 
  will be in this order: Prekey Message ECDH proof, Prekey Message DH proof, 
  Prekey Profile ECDH proof. If `J` is zero, the Prekey Profile ECDH proof 
  will be missing. If `N` is zero, the two Prekey Message proofs will be missing.

Prekey MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the Prekey Profile, if present.
```

### Storage Information Request Message

This is the message sent when you want to know how many Prekey Messages there
are in storage. Only the publisher of those Prekey Messages will receive a
response to this message. This message must be attached to a DAKE-3 message.

A valid "Storage Information Request message" is generated as follows:

1. Calculate the `Storage Information MAC`:
   `KDF(usage_storage_info_MAC, prekey_mac_k || message type, 64)`

To verify a Storage Information Request message

1. Verify that the message type is `0x09`.
1. Verify that the protocol version of the message is `0x0004` or a higher
   version of the protocol. Abort if it is not.
1. Calculate the `Storage Information MAC`:
   `KDF(usage_storage_info_MAC, prekey_mac_k || message type, 64)`
1. Verify that this calculated `Storage Information MAC` is equal to the
   received one. Abort if it is not.

The encoding looks like this:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  This message has type 0x09.

Storage Information MAC (MAC)
  The MAC with the appropriate MAC key of the message type.
```

### Storage Status Message

The "Storage Status message" is sent by the Prekey Server in response to a
"Storage Information Request message".

A valid "Storage Status message" is generated as follows:

1. Calculate the `Status MAC`:
   `KDF(usage_status_MAC, prekey_mac_k || message type ||
    receiver instance tag || Stored Prekey Messages Number, 64)`

To verify a Storage Status message:

1. Verify that the message type is `0x0B`.
1. Verify that the protocol version of the message is `0x0004` or a higher
   version of the protocol. Abort if it is not.
1. Calculate the `Status MAC`:
   `KDF(usage_status_MAC, prekey_mac_k || message type ||
    receiver instance tag || Stored Prekey Messages Number, 64)`
1. Verify that this calculated `Status MAC` is equal to the
   received one. Abort if it is not.

It must be encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  The message has type 0x0B.

Receiver instance tag (INT)
  The instance tag of the intended recipient.

Stored prekey messages number (INT)
  The number of prekey messages stored in the Prekey Server for the
  long-term public key and instance tag used during the DAKE.

Status MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the stored prekey messages number.
```

### Success Message

The "Success message" is sent by the Prekey Server when an action (storing
Prekey Messages, for example) has been successful.

A valid "Success message" is generated as follows:

1. Calculate the `Success MAC`:
   `KDF(usage_success_MAC, prekey_mac_k || message type ||
    receiver instance tag, 64)`

To verify a Success message:

1. Verify that the message type is `0x06`.
1. Verify that the protocol version of the message is `0x0004` or a higher
   version of the protocol. Abort if it is not.
1. Calculate the `Success MAC`:
   `KDF(usage_success_MAC, prekey_mac_k || message type ||
    receiver instance tag, 64)`
1. Verify that this calculated `Success MAC` is equal to the
   received one. Abort if it is not.

It must be encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  The message has type 0x06.

Receiver instance tag (INT)
  The instance tag of the intended recipient.

Success MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the Success message.
```

### Failure Message

The "Failure message" is sent by the Prekey Server when an action (storing a
Prekey Message, for example) has not been successful. This can happen when the
Prekey Server storage is full, for example.

A valid "Failure message" is generated as follows:

1. Calculate the `Failure MAC`:
   `KDF(usage_failure_MAC, prekey_mac_k || message type ||
    receiver instance tag, 64)`

To verify a Failure message:

1. Verify that the message type is `0x05`.
1. Verify that the protocol version of the message is `0x0004` or a higher
   version of the protocol. Abort if it is not.
1. Calculate the `Failure MAC`:
   `KDF(usage_failure_MAC, prekey_mac_k || message type ||
    receiver instance tag, 64)`
1. Verify that this calculated `Failure MAC` is equal to the
   received one. Abort if it is not.

It must be encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  The message has type 0x05.

Receiver instance tag (INT)
  The instance tag of the intended recipient.

Failure MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the Failure message.
```

## Proofs

The section details how to generate and verify the proofs that the prekey server
requires in order to be certain that the values submitted in the Prekey Profile
and the Prekey Messages correspond to secrets that are under control of the
publisher. In order to make these proofs efficient, we use a batch
zero-knowledge proof of knowledge protocol based on the RME common-base Schnorr
protocol detailed in Henry [\[5\]](#references). We use a Fiat-Shamir heuristic
to turn this into a non-interactive protocol by using random values that are
deterministically generated from the shared secret calculated in the DAKE.

There are three values we need to generate proofs for. These are
- The Public Shared Prekey from the Prekey Profile (`D`)
- The Prekey Owner ECDH public key from the Prekey Message (`Y`)
- The Prekey Owner DH public key from the Prekey Message (`B`)

Since publication will usually publish several prekey messages, and we would
like to avoid submitting separate proofs for all the values in the prekey
messages, we will use batch versions of the zero-knowledge proof protocols, so
that we can submit one proof for all the prekey messages, in one go. For
simplicity we will use the same algorithm for the prekey profile, even though
there will only ever be one proof necessary there.

Since the Prekey Message ECDH and DH public keys are in different domains, we do
need separate proofs for them, thus giving us three different proofs.

In all the generation and verification procedures that follow we will be using these two values:

```
  * lambda = 352 (integer)
  * m = KDF(usage_proof_context, SK, 64)
```

### Prekey Profile proof

The Prekey Profile proof will be a zero-knowledge proof of knowledge of the
private value `d` that correspond to the submitted value `D`.

#### Generation

In order to generate the proof for `D`, this procedure should be followed:

```
- pick a random value 'r' (56 bytes) - this can't be all zeroes
- interpret 'r' as a scalar and calculate 'A' as G * r
- compute 'c' as KDF(usage_proof_shared_ecdh, A || D || m, 64)
- compute 'p' as KDF(usage_proof_c_lambda, c, lambda)
- compute 'v' as (r + p * d) mod q
- the proof is 'c' and 'v'
```

#### Verification

In order to verify the proof for `D`, this procedure should be followed:

```
- compute 'p' as KDF(usage_proof_c_lambda, c, lambda)
- compute 'A' as G * v + ((D * p) * -1)
- compute 'c2' as KDF(usage_proof_shared_ecdh, A || D || m, 64)
- verify that 'c' is equal to 'c2'
```

### Prekey Messages proofs

There are two different values in a Prekey Message that needs to be proven. In
order to generate and verify these proofs we assume that there are `N` messages
and that they are indexed with `i`, going from 1 to `N`. The values will be
denoted as `Y_i`, `y_i`, `B_i` and `b_i`.

#### ECDH

This section specifies how to generate the proof for the `N` values `Y_i` and `y_i`.

##### Generation

In order to generate the proof for `N` values `Y_i`, this procedure should be
followed:

```
- pick a random value 'r' (56 bytes) - this can't be all zeroes
- interpret 'r' as a scalar and calculate 'A' as G * r
- compute 'c' as KDF(usage_proof_message_ecdh, A || Y_1 || Y_2 || ... || Y_N || m, 64)
- compute 'p' as KDF(usage_proof_c_lambda, c, N * lambda)
- divide 'p' into 'N' 'lambda'-sized pieces, and denote them as 't_n', starting from 't_1'
- compute 'v' as (r + t_1 * y_1 + t_2 * y_2 + ... + t_n * y_n) mod q
- the proof is 'c' and 'v'
```

##### Verification

In order to verify the proof for `N` values `Y_i`, this procedure should be followed:

```
- compute 'p' as KDF(usage_proof_c_lambda, c, N * lambda)
- divide 'p' into 'N' 'lambda'-sized pieces, and denote them as 't_n', starting from 't_1'
- compute 'A' as G * v + ((Y_1 * t_1 + Y_2 * t_2 + ... + Y_n * t_n) * -1)
- compute 'c2' as KDF(usage_proof_message_ecdh, A || Y_1 || Y_2 || ... || Y_N || m, 64)
- verify that 'c' is equal to 'c2'
```

#### DH

This section specifies how to generate the proof for the `N` values `B_i` and `b_i`.

##### Generation

In order to generate the proof for `N` values `B_i`, this procedure should be
followed:

```
- pick a random value 'r' (80 bytes) - this can't be all zeroes
- interpret 'r' as an MPI and calculate 'A' as g3 ^ r
- compute 'c' as KDF(usage_proof_message_dh, A || B_1 || B_2 || ... || B_N || m, 64)
- compute 'p' as KDF(usage_proof_c_lambda, c, N * lambda)
- divide 'p' into 'N' 'lambda'-sized pieces, and denote them as 't_n', starting from 't_1'
- compute 'v' as (r + t_1 * y_1 + t_2 * y_2 + ... + t_n * y_n) mod dh_q
- the proof is 'c' and 'v'
```
##### Verification

In order to verify the proof for `N` values `B_i`, this procedure should be followed:

```
- compute 'p' as KDF(usage_proof_c_lambda, c, N * lambda)
- divide 'p' into 'N' 'lambda'-sized pieces, and denote them as 't_n', starting from 't_1'
- compute 'A' as g3 ^ v * ((B_1^t_1 * B_2^t_2 * ... * B_n^t_n)^-1)
- compute 'c2' as KDF(usage_proof_message_dh, A || B_1 || B_2 || ... || B_N || m, 64)
- verify that 'c' is equal to 'c2'
```
## State Machine

This is the state machine for when a client wants to publish Client Profiles,
Prekey Profiles or Prekey Messages to the Prekey Server, or when it queries for
the status.

Protocol States:

```
IN_DAKE:
  This is the state where a client has sent a DAKE-1 message, or when the Prekey
  Server has sent a DAKE-2 message.

NOT_IN_DAKE:
  This is the state where a client or the Prekey Server is not in the
  'IN_DAKE' state.
```
There are four events an OTRv4 client must handle:

* Starting the DAKE
* Receiving a DAKE-1 message
* Receiving a DAKE-2 message
* Receiving a DAKE-3 message

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

* If the Prekey Server is in state IN_DAKE:

  * Transitions to NOT_IN_DAKE state.

* Otherwise:

  * Ignores the message.

## Publishing Prekey Values

```
Alice                                                Prekey Server
----------------------------------------------------------------------------------------
Sends a DAKE-1 message               ------------->

                                     <-------------  Receives a DAKE-1 message and
                                                     sends a DAKE-2 message

Receives a DAKE-2 message and
sends a DAKE-3 message with a
Prekey Publication message           ------------->

                                     <-------------  Receives a DAKE-3 message and
                                                     stores the Client Profile and
                                                     the Prekey Profile (if present),
                                                     and the Prekey Messages.
                                                     Sends a Success message.
```

Notice that this section refers to the ideal functionality of a Prekey Server.
Consider that a Prekey Server can, for example, decide to not perform some of
the verifications noted here.

By "client" we mean each device a user has.

1. Client creates the Client Profile, as defined in the OTRv4 specification. See
   the [Client Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#client-profile)
   section of the OTRv4 specification for details.
1. Client creates the Prekey Profile, as defined in OTRv4 specification. See
   the [Prekey Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-profile)
   section of the OTRv4 specification for details.
1. Client creates Prekey Messages, as defined in OTRv4 specification. See
   the [Prekey message](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-message)
   section of the OTRv4 specification for details.
1. Client receives a Prekey Server Identity (e.g. prekey.example.org) with the
   the Prekey Server long-term public key from a source. In XMPP, for example,
   this source is the Prekey Server' service discovery functionality.
1. Client authenticates (in a deniable way) with the Prekey Server through the
   DAKE and, with that, it generates a shared secret.
   See section [Key Exchange](#key-exchange) for details.
1. Client sends the Client Profile, and the Prekey Profile (if needed), and
   Prekey Messages to the Prekey Server in the final message of the DAKE (DAKE-3
   with a 'Prekey Publication message" attached).
   See the [Prekey Publication message](#prekey-publication-message) section for
   details.
1. The Prekey Server verifies the received values:
   1. Validate the Prekey Publication message, as defined in its section
      [Prekey Publication Message](#prekey-publication-message).
   1. For every value, check the integrity of it.
   1. If Client and Prekey Profile are present:
      1. Validate the Client Profile as defined in the
         [Validating a Client Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-client-profile)
         section of the OTRv4 specification.
      1. Validate the Prekey Profile as defined in the
         [Validating a Prekey Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-prekey-profile)
         section of the OTRv4 specification.
   1. If Prekey Messages are present:
      1. Validate the Prekey Messages as defined in the
         [Prekey Message](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-message)
         section of the OTRv4 specification.
   1. Discard any invalid or duplicated values.
1. The Prekey Server stores the Client Profile, Prekey Profile and Prekey
   Messages by associating them with the identity. This identity is the one used
   by the network, for example, `alice@xmpp.org` for XMPP.
1. The Prekey Server sends an acknowledgment that the operation succeeded in the
   form of a "Success message". See [Success Message](#success-message) for
   details.

## Retrieving Prekey Ensembles

```
Bob                                                  Prekey Server
----------------------------------------------------------------------------------------
Sends a Prekey Ensemble Query
Retrieval message (which specifies
Alice's identity
-for example, alice@xmpp.org-
and versions -"45"-)                 ------------->

                                     <-------------  Sends Prekey Ensembles for
                                                     alice@xmpp.org

Receives Prekey Ensembles and
verifies them.
```

In order to send an encrypted offline message, a client must obtain a Prekey
Ensemble from the participant they want to start a conversation with:

1. Client sends a [Prekey Ensemble Query Retrieval message](#prekey-ensemble-query-retrieval-message),
   which specifies which identity and protocol versions it wants Prekey Ensembles
   for. It also specifies from which device it's talking, by defining the
   sender instance tag, so the Prekey Server knows to which device to
   respond to.
1. The Prekey Server checks if there are any Prekey Ensembles available for the
   identity and for the versions advertised in the "Prekey Ensemble Query
   Retrieval message". If there are none (or any of its values are
   missing), it sends a "No Prekey Ensembles in Storage" message.
1. The Prekey Server selects Prekey Ensembles for each requested versions
   consisting of:
   * A valid Client Profile for every instance tag for the identity.
   * A valid Prekey Profile for every instance tag for the identity.
   * One Prekey Message for every Client Profile and Prekey Profile selected.
     This Prekey Messages must have the same instance tag as the Client and
     Prekey Profile.
   * Builds Prekey Ensembles with the selected values, for example:

     ```
     Identity || Client Profile (with instance tag 0x01, and long-term public key 1) ||
     Prekey Profile (with instance tag 0x01 and long-term public key 1) ||
     Prekey Message (with instance tag 0x01).

     Identity || Client Profile (with instance tag 0x02, and long-term public key 2) ||
     Prekey Profile (with instance tag 0x02 and long-term public key 2) ||
     Prekey Message (with instance tag 0x02).
     ```

1. The Prekey Server delivers all selected Prekey Ensembles to the Client in the
   form of a [Prekey Ensemble Retrieval Message](#prekey-ensemble-retrieval-message).
   Uses the instance tag of the retriever as the "receiver instance tag".
1. The Prekey Server removes the selected Prekey Messages from its storage. It
   doesn't delete neither the Client nor the Prekey Profile.
1. If there were no Prekey Ensembles in storage, the Client receives a "No
   Prekey Ensembles in Storage" message. It displays its human-readable part.
1. If there were, the Client receives a "Prekey Ensemble Retrieval message":
   1. Verifies that the receiver instance tag of it is equal to its sender
      instance tag.
1. For each requested version, the Client receives the Prekey Ensembles and:
   1. Checks that there are `L` number of Prekey Ensembles as stated in the
      "Prekey Ensemble Retrieval message".
   1. Checks that there is at least one Client Profile, one Prekey Profile and
      one Prekey Message.
   1. Groups all Prekey Messages by instance tag.
   1. Validates all Prekey Ensembles:
      1. Checks that all the instance tags on the Prekey Ensemble's values are
         the same.
      1. [Validates the Client Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-client-profile).
      1. [Validates the Prekey Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-prekey-profile).
      1. Checks that the Prekey Profile is signed by the long-term public stated
         in the Client Profile.
      1. Verifies the Prekey Message as stated in the
         [Prekey Message](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-message)
         section.
      1. Checks that the OTR version of the Prekey Message matches one of the
         versions signed in the Client Profile contained in the Prekey Ensemble.
      1. Checks if the Client Profile's version is supported by the client.
      1. Chooses the Prekey Ensemble with the latest expiry time from each
         group.
   1. Discards any invalid or duplicated Prekey Ensembles.
1. Client chooses which Prekey Ensembles to send an encrypted offline message
   to:
   1. A client can optionally only use Prekey Ensembles that contain trusted
      long-term public keys.
   1. If there are several instance tags in the list of Prekey Ensembles, the
      client can optionally decide which instance tags to send messages to.
      Inform the user if the encrypted messages will be send to multiple
      instance tags (multiple devices).
   1. If there are multiple Prekey Ensembles per instance tag, decides whether
      to send multiple messages to the same instance tag.

### Prekey Ensemble Query Retrieval Message

The encoding of this message looks like this:

```
Protocol version (SHORT)
  The version number of this OTR protocol is 0x0004.

Message type (BYTE)
  The message has type 0x10.

Sender instance tag (INT)
  The instance tag of the sender.

Participant Identity (DATA)
  The identity of the participant you are asking Prekey Ensembles for. In the
  case of XMPP, for example, this is the bare jid.

Versions (DATA)
  The OTR versions you are asking Prekey Ensembles for. A valid versions string
  can be created by concatenating the version numbers together in any order.
  For example, a user who wants Prekey Ensembles for versions 4 and 5 will have
  the 2-byte version string "45" or "54". Unrecognized versions should be
  ignored.
```

### Prekey Ensemble Retrieval Message

The encoding of this message looks like this:

```
Protocol version (SHORT)
  The version number of this OTR protocol is 0x0004.

Message type (BYTE)
  The message has type 0x13.

Receiver instance tag (INT)
  The instance tag of the intended recipient.

L (INT)
  The number of Prekey Ensembles. It must be greater than 0.

Ensembles
  The concatenated Prekey Ensembles. Each Ensemble is encoded as:

   Client Profile (CLIENT-PROF)
   Prekey Profile (PREKEY-PROF)
   Prekey Message
      Prekey Messages are encoded as specified in OTRv4 specification, section
      'Prekey Message'.
```

### No Prekey Ensembles in Storage Message

This message is sent by the Prekey Server when it runs out of Prekey Messages,
or when it does not have a Client or Prekey Profile.

The encoding looks like this:

```
Protocol version (SHORT)
  The version number of this OTR protocol is 0x0004.

Message type (BYTE)
  The message has type 0x0E.

Receiver instance tag (INT)
  The instance tag of the intended recipient.

No Prekey-Messages message (DATA)
  The human-readable details of this message. It contains the string "No Prekey
  Messages available for this identity".
```

## Query the Prekey Server for its Storage Status

```
Alice                                                Prekey Server
----------------------------------------------------------------------------------------
Sends a DAKE-1 message               ------------->

                                     <-------------  Receives a DAKE-1 message and
                                                     sends a DAKE-2 message

Receives a DAKE-2 message and
sends a DAKE-3 message with a
Storage Information Request message  ------------->

                                     <-------------  Receives a DAKE-3 message and
                                                     sends a Storage Status message
```

1. Client uses DAKEZ to authenticate with the Prekey Server. See section
   [Key Exchange](#key-exchange) for details.
2. The Prekey Server responds with a "Storage Status message" containing the
   number of Prekey Messages stored for the long-term public key, identity and
   instance tag used during the DAKEZ.

## Fragmentation of some Messages

There are two messages in this specification that can be fragmented: the
"prekey publication" message and the "prekey ensemble retrieval" message.

Some networks may have a maximum message size that is too small to contain an
encoded OTR-prekey-server message. In that event, the sender may choose to split
the message into a number of fragments. This section describes the format for
the fragments.

The OTRv4-prekey-server fragmentation and reassembly procedure needs to be able
to break data messages into an almost arbitrary number of pieces that can be
later reassembled. The receiver of the fragments uses the identifier field to
ensure that fragments of different data messages are not mixed. The fragment
index field tells the receiver the position of a fragment in the original data
message. These fields provide sufficient information to reassemble data
messages.

All OTRv4-prekey-server clients must be able to reassemble received fragments,
but performing fragmentation on outgoing messages is optional.

### Transmitting Fragments

If you have information about the maximum message size you are able to send
(different IM networks have different limits), you can fragment an encoded
OTR-prekey-server message as follows:

  * Start with the OTRv4-Prekey message as you would normally transmit it. For
    example, a Prekey Publication Message would start with
    `AAQD` and end with `.`.
  * Assign an identifier, which will be used specifically for this fragmented
    data message. This is done in order to not confuse these fragments with
    other message's fragments. The identifier is a unique randomly generated
    4-byte value that must be unique for the time the message is fragmented.
  * Break it up into sufficiently small pieces. Let this number of pieces be
    `total`, and the pieces be `piece[1],piece[2],...,piece[total]`.
  * Transmit `total` OTRv4-prekey-server fragmented messages with the following
    (printf-like) structure (as `index` runs from 1 to `total` inclusive:

  ```
  "?OTRP|%x|%x|%x,%hu,%hu,%s,", identifier, sender_instance, receiver_instance, index, total, piece[index]
  ```

The message should begin with `?OTRP|` and end with `,`.

Note that `index` and `total` are unsigned short int (2 bytes), and each has a
maximum value of 65535. Each `piece[index]` must be non-empty. The `identifier`,
instance tags, `index` and `total` values may have leading zeros.

Note that fragments are not messages that can be fragmented: you can't fragment
a fragment.

### Receiving Fragments

A reassemble process does not to be implemented in precesely the way we are
going to describe; but the process implemented in a library has to be able to
correctly reassemble the fragments.

If you receive a message starting with `?OTRP|`:

  * Parse it (as the previous printf structure) extracting the `identifier`,
    the instance tags, `index`, `total`, and `piece[index]`.

  * If the message is a "Prekey Ensemble Retrieval" message, discard the message and
    optionally pass a warning to the participant if:
    * The recipient's own instance tag does not match the listed receiver
      instance tag.
    * The listed receiver's instance tag is not zero.

  * Discard the (illegal) fragment if:
    * `index` is 0
    * `total` is 0
    * `index` is bigger than `total`

  * For the first fragment that arrives (there is not a current buffer with the
    same `identifier`):
    * Create a buffer which will keep track of the portions of the fragmented
      message that have arrived (by filling up it with fragments).
    * Optionally, initialize a timer for the reassembly of the fragments as it
      is possible that some fragments of the message might never show up.
      This timer ensures that a client will not be waiting "forever" for a
      fragment. If the timer runs out, all stored fragments in this buffer
      should be discarded.
    * Let `B` be the buffer, `I` be the currently stored identifier, `T` the
      currently stored `total` and `C` a counter that keeps track of the
      received number of fragments for this buffer. If you have no currently
      stored fragments, there are no buffers, and `I`, `T` and `C` equal 0.
    * Set the length of the buffer as `total`: `len(B) = total`.
    * If the `index` is empty, store `piece` at the `index` given position:
      `insert(piece, index)`. If it is not, reject the fragment and do not
      increment the buffer counter.
    * Let `total` be `T` and `identifier` be `I` for the buffer.
    * Increment the buffer counter: `C = C + 1`.

  * If `identifier == I`:
    * If `total == T`, and `C < T`:
      * Check that the given position of the buffer is empty:
        `B[index] == NULL`. If it is not, reject the fragment and do not
        increment the buffer counter.
      * Store the `piece` at the given position in the buffer:
        `insert(piece, index)`.
      * Increment the buffer counter: `C = C + 1`.
    * Otherwise:
      * Forget any stored fragments of this buffer you may have.
      * Reset `C` and `I` to 0, and discard this buffer.

  * Otherwise:
    * Consider this fragment as part of another buffer: either create a new
      buffer or insert the fragment into one that has already been created.

After this, if the current buffer's `C == T`, treat the buffer as the received
message.

If you receive an unfragmented message:

* Keep track of the buffers you may already have. Do not discard them.

## A Prekey Server for OTRv4 over XMPP

This segment defines a sub specification which declares how a prekey server
implementation has to work with XMPP. For interoperability, this style of
specification will need to be created for other networks as well. The XMPP
specific part of this specification is not a necessary part of the rest of the
OTR Prekey Specification - it is possible to implement a compliant prekey server
that does not implement this section.

### Discovering a Prekey Server

A participant will find information about a prekey serve reading the Service
Discovery specification (XEP-0030). The first lookup will be a lookof up items
to the containing server:

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
            name='OTR Prekey Server'/>
    </query>
  </iq>
```

In order to find an OTRv4 compliant prekey server, Alice then needs to send a
info request to all items returned from the original call:

```
  <iq from='alice@xmpp.org/notebook'
      id='info1'
      to='prekey.xmpp.org'
      type='get'>
    <query xmlns='http://jabber.org/protocol/disco#info'/>
  </iq>
```

For a compliant server, this will return the feature
`http://jabber.org/protocol/otrv4-prekey-server` and an identity that has category
`auth` and type `otr-prekey`:

```
<iq type='result'
    from='prekey.xmpp.org'
    to='alice@xmpp.org/notebook'
    id='info1'>
  <query xmlns='http://jabber.org/protocol/disco#info'>
    <identity
        category='auth'
        type='otr-prekey'
        name='OTR Prekey Server'/>
    <feature var='http://jabber.org/protocol/disco#info'/>
    <feature var='http://jabber.org/protocol/disco#items'/>
    <feature var='http://jabber.org/protocol/otrv4-prekey-server'/>
  </query>
</iq>
```

Finally, before starting to use a prekey server, you also need to lookup for the
fingerprint for this server. This can be find by doing a lookup for items on the
server:

```
  <iq from='alice@xmpp.org/notebook'
      id='items1'
      to='prekey.xmpp.org'
      type='get'>
    <query xmlns='http://jabber.org/protocol/disco#items'/>
  </iq>
```

This should return an item where node has the value `fingerprint`, and the name
will contain the hexadecimal representation of the fingerprint:

```
<iq type='result'
    from='prekey.xmpp.org'
    to='alice@xmpp.org/notebook'
    id='items1'>
  <query xmlns='http://jabber.org/protocol/disco#items'>
    <item jid='prekey.xmpp.org'
          node='fingerprint'
          name='3B72D580C05DE2823A14B02B682636BF58F291A7E831D237ECE8FC14DA50A187A50ACF665442AB2D140E140B813CFCCA993BC02AA4A3D35C'/>
  </query>
</iq>
```

The fingerprint will, for OTRv4 keys, always be 112 hexadecimal digits that can
be decoded into a 56-byte value, following the instructions in the OTRv4
specification.

If the server returns more than one prekey server in its list of items, anyone
should be able to use it. All prekey servers exposed by an XMPP server have to
share the same storage. Thus, a client should randomly choose one of the
returned prekey servers to connect to, in order to distribute load for the
server.

### Publishing Prekey Values to the Server

An entity authenticates to the server through an interactive DAKE. DAKE
messages are sent in "message" stanzas.

When calculating the `phi` value for XMPP, the bare JID of the publisher and the
bare jid of the server has to be used:

```
  phi = DATA("alice@xmpp.org") || DATA("prekey.xmpp.org")
```

An entity starts the DAKE by sending the first encoded message in the body
of a message:

```
  <message
      from='alice@xmpp.org/notebook'
      id='nzd143v8'
      to='prekey.xmpp.org'>
    <body>AAQ1...</body>
  </message>
```

The server responds with the subsequent DAKE message:

```
  <message
      from='prekey.xmpp.org'
      id='13fd16378'
      to='alice@xmpp.org/notebook'>
    <body>AAQ2...</body>
  </message>
```

And the entity terminates the DAKE and sends the prekey values attached to the
last DAKE message:

```
  <message
      from='alice@xmpp.org/notebook'
      id='kud87ghduy'
      to='prekey.xmpp.org'>
    <body>AAQ3...</body>
  </message>
```

And the Prekey Server responds with a "Success" message:

```
  <message
      from='prekey.xmpp.org'
      id='0kdytsmslkd'
      to='alice@xmpp.org/notebook'>
    <body>AAQG...</body>
  </message>
```

### Obtaining Information about Prekey Messages from the Server

An entity authenticates to the server through a DAKE. DAKE messages are send
in "message" stanzas.

It sends the same DAKE messages as the previous section, except for the attached
message in the last DAKE-3 message.

And the entity terminates the DAKE and asks for storage information:

```
  <message
      from='alice@xmpp.org/notebook'
      id='kud87ghduy'
      to='prekey.xmpp.org'>
    <body>AAQ3...</body>
  </message>
```

And the Prekey Server responds with a "Storage Status" message:

```
  <message
      from='prekey.xmpp.org'
      id='0kdytsmslkd'
      to='alice@xmpp.org/notebook'>
    <body>AAQL...</body>
  </message>
```

### Retrieving published Prekeys Ensembles from a Prekey Server

An entity asks the server for Prekey Ensembles from a particular participant by
sending a "Prekey Ensemble Query Retrieval message" for an specific identity,
for example, `bob@xmpp.net`, and specific versions, for example, "45".

```
  <message
      from='alice@xmpp.org/notebook'
      id='nzd143v8'
      to='prekey.xmpp.org'>
    <body>AAQQ...</body>
  </message>
```

The server responds with a "Prekey Ensemble Retrieval message" if there are
values in storage:

```
  <message
      from='prekey.xmpp.org'
      id='13fd16378'
      to='alice@xmpp.org/notebook'>
    <body>AAQT...</body>
  </message>
```

The server responds with a "No Prekey-Ensembles in Storage message" if there
are no values in storage:

```
  <message
      from='prekey.xmpp.org'
      id='13fd16378'
      to='alice@xmpp.org/notebook'>
    <body>AAQO...</body>
  </message>
```

## Storage of Prekeys Ensembles for XMPP

The storage for prekeys will use the bare JID to identify client profiles,
prekey profiles and prekey messages. Instance tags will be used to differentiate
data for different clients. Since XMPP resources are not stable between
invocations of most XMPP software, resources can't be used as a mechanism for
storage.

## Detailed Example of the Prekey Server over XMPP

`bob@xmpp.org/notebook` wants to know how many Prekeys Messages remain unused:

1. `bob@xmpp.org/notebook` logs in to his server (`talk.xmpp.org`).
1. `bob@xmpp.org/notebook` uses service discovery to find a Prekey Server in his
   server (`prekey.xmpp.org`).
   1. Bob sends service discovery information messages to all returned nodes, by
      looking at the results, he identifies all prekey server nodes.
   1. Bob then chooses one of them randomly.
   1. Finally, he sends a service discovery items message to the Prekey Server
      in order to retrieve the fingerprint for this server.
1. `bob@xmpp.org/notebook` asks `prekey.xmpp.org` about the number of Prekeys
   messages it has stored for him:
   1. `bob@xmpp.org/notebook` deniably authenticates by using DAKEZ with
      `prekey.xmpp.org`.
   1. `bob@xmpp.org/notebook` sends a "Storage Status Message" attached to the
       last DAKEZ message to `prekey.xmpp.org`.
   1. `bob@xmpp.org/notebook` receives a "Storage Status Message" message
      from `prekey.xmpp.org`.

`bob@xmpp.org/notebook` wants to publish prekey messages to the Prekey Server:

1. `bob@xmpp.org/notebook` logs in to his server (`talk.xmpp.org`).
1. `bob@xmpp.org/notebook` uses service discovery to find a Prekey Server in his
   server (`prekey.xmpp.org`).
   1. Bob sends service discovery information messages to all returned nodes. By
      looking at the results, he identifies all prekey server nodes.
   1. He then chooses one of them randomly.
   1. Finally, he sends a service discovery items message to the Prekey Server
      in order to retrieve the fingerprint for this server.
1. `bob@xmpp.org/notebook` wants to publish a Client Profile, a Prekey Profile
   and 5 Prekey messages to `prekey.xmpp.org`:
   1. `bob@xmpp.org/notebook` deniably authenticates by using DAKEZ with
      `prekey.xmpp.org`.
   1. `bob@xmpp.org/notebook` sends a "Prekey Publication Message" attached to
      the last DAKEZ message to `prekey.xmpp.org` (with the values of the prekey
      messages).
   1. `bob@xmpp.org/notebook` receives a "Success" or "Failure" message from
      `prekey.xmpp.org` if the above operation was successful or not.

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
5. Henry, R (2014). *Efficient Zero-Knowledge Proofs and Applications* Available at: https://uwspace.uwaterloo.ca/bitstream/handle/10012/8621/Henry_Ryan.pdf
