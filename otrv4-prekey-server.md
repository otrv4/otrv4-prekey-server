# OTRv4 Prekey Server

```
Disclaimer

This protocol specification is a draft.
```

OTRv4 Prekey Server provides an additional specification to the OTRv4 [\[1\]](#references)
protocol when it needs an untrusted central Prekey Server to store prekey
messages.

## Table of Contents

1. [High Level Overview](#high-level-overview)
1. [Assumptions](#assumptions)
1. [Security Properties](#security-properties)
1. [Prekey Server Requirements](#prekey-server-specifications)
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
   1. [Shared secrets](#shared-secrets)
   1. [Generating Shared Secrets](#generating-shared-secrets)
1. [Key Exchange](#key-exchange)
   1. [DAKE-1 Message](#dake-1-message)
   1. [DAKE-2 Message](#dake-2-message)
   1. [DAKE-3 Message](#dake-3-message)
   1. [Prekey Publication Message](#prekey-publication-message)
   1. [Storage Information Request Message](#storage-information-request-message)
   1. [Storage Status Message](#storage-status-message)
   1. [No Prekey Ensembles on Storage Message](#no-prekey-ensembles-on-storage-message)
   1. [Success Message](#success-message)
   1. [Failure Message](#failure-message)
1. [State machine](#state-machine)
1. [Publishing Prekey Values](#publishing-prekey-values)
1. [Retrieving Prekey Ensembles](#retrieving-prekey-ensembles)
   1. [Prekey Ensemble Retrieval Message](#prekey-ensemble-retrieval-message)
   1. [No Prekey Ensembles on Storage Message](#no-prekey-ensembles-on-storage-message)
1. [Query the Prekey Server for its storage status](#query-the-prekey-server-for-its-storage-status)
1. [A Prekey Server for OTRv4 over XMPP](#a-prekey-server-for-otrv4-over-xmpp)
   1. [Discovering a prekey service](#discovering-a-prekey-service)
   1. [Discovering the features supported by a prekey service](#discovering-the-features-supported-by-a-prekey-service)
   1. [Publishing prekey values to the service](#publishing-prekey-values-to-the-service)
   1. [Obtaining information about prekey messages from the service](#obtaining-information-about-prekey-messages-from-the-service)
   1. [Retrieving published prekeys from a prekey service](#retrieving-published-prekeys-from-a-prekey-service)
1. [Detailed example of the prekey server over XMPP](#detailed-example-of-the-prekey-server-over-xmpp)
1. [References](#references)

## High Level Overview

The OTRv4 Prekey Server specification defines a way by which parties can
publish and store Client Profiles, Prekey Profiles and Prekey Messages, and
retrieve Prekey Ensembles from an untrusted Prekey Server. A Prekey Ensemble
contains the publisher's Client Profile, the publisher's Prekey Profile and one
prekey message (which contains one-time use ephemeral public prekey values), as
defined in the OTRv4 specification [\[1\]](#references). These Prekey Ensembles
are used for starting offline conversations.

The OTRv4 specification defines a non-interactive DAKE, which is derived from
the XZDH protocol. This DAKE begins when Alice, who wants to initiate an offline
conversation with Bob, asks an untrusted Prekey Server for a Prekey Ensemble for
Bob. The values for the Prekeys Ensembles have previously been stored in
the Prekey Server by a request from Bob.

This document aims to describe how the untrusted Prekey Server can be used to
securely publish, store and retrieve prekey ensembles and its values.

## Assumptions

The OTRv4 Prekey Server specification can not protect against an active
attacker performing Denial of Service attacks (DoS).

This specification aims to support future OTR versions. Because of that, the
Prekey Server should support multiple prekey messages from different/future
OTR versions, starting with the current version, 4.

## Security Properties

OTRv4 states the need for a service provider that stores key material used in
a deniable trust establishment for offline conversations. This service provider
is the Prekey Server, as establish in this specification.

There are three things that should be uploaded to the Prekey Server: client
profiles, prekey profiles and prekey messages. They are needed for starting a
non-interactive DAKE. Prekey profiles are needed as if only prekey messages are
used for starting non-interactive conversations, an active adversary can modify
the first flow from the publisher to use an adversarially controlled ephemeral
key, capture and drop the response from the retriever, and then compromise the
publisher's long-term secret key. The publisher will never see the messages, and
the adversary will be able to decrypt them. Moreover, since long-term keys are
usually meant to last for years, a long time may pass between the retriever
sending the messages and the adversary compromising the publisher's long-term
key. This attack is mitigated with the use of Prekey Profiles that contain
shared prekeys signed by the long-term secret key, and that are reusable.

A Prekey Server can also be used to publish the Client Profile, even if OTRv4 is
implemented in the OTRv4-interactive-only mode. This should be done in order to
achieve deniability properties, as it allows two parties to send and verify each
other's Client Profile during the DAKEs without damaging participation
deniability for the conversation, since the Client Profile becomes public
information.

The submissions of these values to the untrusted Prekey Server are deniably
authenticated by using DAKEZ. If they were not authenticated, malicious
users could perform denial-of-service attacks (DoS). In order to preserve the
deniability properties of the whole OTRv4 protocol, they should be deniably
authenticated.

Furthermore, in order to safeguard the integrity of the submitted values to the
Prekey Server, a MAC of those values is used. The Prekey Server should validate
this MAC after receiving the values.

Note that the Prekey Server is untrusted and therefore can cause the
communication between two parties to fail. This can happen in several ways:

- The Prekey Server refuses to hand out Prekey Ensembles.
- The Prekey Server hands out incomplete Prekey Ensembles.
- The Prekey Server hands out expired Prekey Ensembles.
- The Prekey Server hands out Prekey Messages that have been used.
- The Prekey Server reports incorrect number of stored Prekey Ensembles.

Notice that the security of the non-Interactive DAKE (XZDH) in the OTRv4
specification does not require trusting the Prekey Server. However, if we allow
a scenario in which the user’s keys have been compromised but the Prekey Server
has not, then we can achieve better plausible deniability. The user may ask the
Prekey Server in advance to assist with a forged conversation, casting doubt on
all conversations conducted by an online adversary using the compromised device.

## Prekey Server Requirements

The Prekey Server used in this specification should be considered untrusted.
This means that a malicious server could cause communication between parties to
fail, as stated above.

The Prekey Server must have these capabilities:

- Receive client profiles, prekey profiles and a set of prekey messages, and
  store them by the corresponding identity. Inform that this operation have
  failed or has been successful.
- Deliver prekey ensembles previously stored.
- Inform the publisher about how many prekey messages are stored for them.
- Inform the retriever when there are no prekey ensembles (or any of its values)
  from an specific party.

The Prekey Server expects to only receive messages on the same network
authenticated clients use to exchange messages. This means that a message
received should be from the same network the publisher is believed to have
been authenticated to.

Although this specification defines expected behavior from the Prekey Server
(e.g., by specifying that client profiles, prekey profiles and prekey messages
submissions should be validated by the Prekey Server), clients should not rely
on this prescribed behavior, as the Prekey Server is untrusted. Verifications
must also be performed by clients as well, even though the Prekey Server should
be expected to perform them. Furthermore, clients working with a Prekey Server
are expected to upload new client profiles and prekey profiles before they
expire or when creating a new long-term public key.

Note that client profiles, prekey profiles and prekey messages submissions to
the untrusted Prekey Server have to be authenticated. If they are not
authenticated, then malicious users can perform denial-of-service attacks. To
preserve the deniability of the overall OTRv4 protocol, prekey messages should
never be digitally signed. This specification uses a DAKEZ exchange between the
publisher and the Prekey Server to fulfill this need, and preserve deniability.

In order to correctly perform the DAKEZ with the publisher, the untrusted Prekey
Server should be able to correctly generate ephemeral ECDH keys and long-term
Ed488-EdDSA keys.

When the Prekey Server runs out of prekey messages, or when it has no
client or prekey profiles, a "No Prekey Ensembles on Storage" message should be
returned, as defined in this [section](#no-prekey-ensembles-on-storage-message).
In theory, it would be possible to return a "multi use" default prekey message.
However, the consequences to participation deniability with this technique are
currently undefined and, thus, risky. Thus, this specification does not use
this kind of fallback behavior. As a consequence, the OTRv4 protocol can be
subject to DoS attacks by an attacker draining the Prekey Messages for another
user. This can be partially mitigated using rate limiting.

Notice that the Prekey Server should be able to support future versions,
starting from version 4. This means that the Prekey Server will accept prekey
ensembles with different versions. For this, the header of a Prekey Message
must remain the same in future versions:

```
Protocol version (SHORT)
  The version number of the protocol, e.g, 0x0004 for OTRv4.

Message type (BYTE)
  The message type, e.g., 0x0F for OTRv4.

Prekey Message Identifier (INT)
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
  KDF(usageID, values, size) = SHAKE-256("OTRv4-Prekey-Server" || usageID || values, size)
```

The `size` first bytes of the SHAKE-256 output for the input
`"OTRv4-Prekey-Server" || usageID || values` will be returned.

Unlike in the SHAKE standard, the output size (`size`) here is in bytes.

## Data Types

The OTRv4 Prekey Server Specification uses many of the data types already
specified in the OTRv4 specification, as defined in section
[Data Types](https://github.com/otrv4/otrv4/blob/master/otrv4.md#data-types)

The OTRv4 Prekey Server Specification also uses the Prekey Server Composite
Identity data type, which is detailed in the
[Prekey Server Composite Identity](#prekey-server-composite-identity) section.

### Encoded Messages

OTRv4 Prekey Server messages must be base-64 encoded. To transmit one of these
messages, construct an ASCII string: the six bytes "?OTRP:", the base-64
encoding of the binary form of the message and the byte ".".

### Public keys and Fingerprints

OTR users have long-lived public keys that they use for authentication (but not
for encryption). The Prekey Server has one as well. It is generated
as defined in the "Public keys, Shared Prekeys and Fingerprints" section of the
OTRv4 specification.

Public keys have fingerprints, which are hex strings that serve as identifiers
for the public key. The full OTRv4 fingerprint is calculated by taking the
SHAKE-256 hash of the byte-level representation of the public key. The long-term
public keys for the Prekey Server have fingerprints as well. The fingerprint is
generated as:

* The first 56 bytes from the `KDF(0x00, byte(H), 56)` (224-bit security
  level), where `H` is the Prekey Server's long-term public key.

### Shared Session State

A Shared Session State between the server and the publisher is needed for
the same reasons as stated in the
[Shared Session State](https://github.com/otrv4/otrv4/blob/master/otrv4.md#shared-session-state)
section of the OTRv4 specification. It is used to authenticate contexts to
prevent attacks that rebind the DAKE transcript into different contexts.

As an example, for a Prekey Server running over XMPP, this should be:

```
  phi = publisher's bare JID || servers's bare JID
```

For example:

```
  phi = "alice@jabber.net/mobile" || "prekeys.xmpp.org"
```

### Prekey Server Composite Identity

For the DAKE performed by a publisher and the Prekey
Server, an identifier is needed. This value will be denoted the "Prekey Server
Identifier".

It is the hash of the Prekey Server identity concatenated with
the Prekey Server long-term public key's fingerprint.

```
Prekey Server Composite Identity (PREKEY-SERVER-COMP-ID):
  Prekey Server Identity (DATA)
  Fingerprint (DATA)
```

For a Prekey Server that uses XMPP, this must be the bare JID of the Prekey
Server (for example, prekey.xmpp.org) and the fingerprint of its long-term
public key:

```
  Prekey Server Composite Identity = "prekey.xmpp.org" || "8625CE01F8D06586DC5B58BB1DC7D9C74F42FB07"
```

## Key Management

In the DAKE between the publisher and the Prekey Server, long-term
Ed448 keys and ephemeral Elliptic Curve Diffie-Hellman (ECDH) keys are used.
Notice that if this DAKE is only used for deniable authentication, the shared
secret derived during the DAKE should be discarded. Nevertheless, this shared
secret can be used with the Double Ratchet Algorithm to either encrypt the
channel or by Prekey Server to encrypt the stored prekey messages
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
    'KDF(0x01, SK_ecdh)'.
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

## Key Exchange

As previously stated, client profiles, prekey profiles and prekey messages
submissions to the Prekey Server have to be authenticated. If they are not
authenticated, malicious users can perform denial-of-service attacks. To
preserve the deniability of the overall OTRv4 protocol, the submissions are
authenticated using a DAKEZ [\[3\]](#references) exchange between the publisher
and the Prekey Server, which preserves deniability.

The following parameters are expected to have been generated:

* `(sk_a, Ha)`: Alice's long-term keypair. As defined in section
   [Public keys, Shared Prekeys and Fingerprints](https://github.com/otrv4/otrv4/blob/master/otrv4.md#public-keys-shared-prekeys-and-fingerprints)
   of the OTRv4 protocol.
* `(sk_s, Hs)`: Server's long-term keypair. As defined in section
   [Public keys, Shared Prekeys and Fingerprints](https://github.com/otrv4/otrv4/blob/master/otrv4.md#public-keys-shared-prekeys-and-fingerprints)
   of the OTRv4 protocol.
* `Alices_Client_Profile`: Alice's Client Profile. As defined in section
   [Creating a Client Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#creating-a-user-profile)
   of the OTRv4 protocol.
* `Prekey_Server_Composite_Identity`: the Prekey Server Composite Identity.

Alice is also expected to have the Prekey Server Composite Identity and the
server long-term public key, so that they can be manually verified by her.

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
1. Generates a DAKE-2 message, as defined in
   [DAKE-2 Message](#dake-2-message) section.
1. Calculates the Shared secret (`SK`):
   * `SK = KDF(0x01, ECDH(s, I))`.
   * Securely erases `s`.
1. Sends Alice the DAKE-2 message (see [DAKE-2 Message](#dake-2-message)
   section).

**Alice**

1. Receives the DAKE-2 message from the Prekey Server.
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
   * `SK = KDF(0x01, ECDH(i, S))`.
   * Securely erases `i`.
1. Calculates the Prekey MAC key: `prekey_mac_k = KDF(0x08, SK, 64)`.
1. Creates a message (`msg`):
   1. If she wants to publish client profiles and prekey profiles, and/or prekey
      messages, she creates a "Prekey Publication message", as defined in
      [Prekey Publication Message](#prekey-publication-message).
   1. If she wants to ask for storage information, she creates a "Storage
      Information Request message", as defined in
      [Storage Information Request Message](#storage-information-request-message).
1. Attaches the corresponding `msg` to the DAKE-3 message, and sends it.

**Prekey Server**

1. Receives the DAKE-3 message from Alice:
   * Verifies the DAKE-3 message as defined in the
     [DAKE-3 message](#dake-3-message) section. If something fails, the server
     rejects the message and does not send anything further.
1. Retrieves the `msg` attached to the DAKE-3 message:
   1. If this is a "Prekey Publication message":
      * Uses the sender's instance tag from the DAKE-3 message as the receiver's
        instance tag and checks that is equal to the previously seen.
      * Calculates the Prekey MAC key: `prekey_mac_k = KDF(0x08, SK, 64)`.
      * Computes the `Prekey MAC`:
        * If client profiles and prekey profiles are present on the message:
          `KDF(0x07, prekey_mac_k || message type || K || client profiles || J
           || prekey profiles || N || prekey messages, 64)`.
        * If only prekey messages are present on the message:
          `KDF(0x07, prekey_mac_k || message type || N || prekey messages, 64)`.
        * Checks that this `Prekey MAC` is equal to the one received in the
          "Prekey publication message". If it is not, the server aborts the DAKE
          and sends a "Failure Message", as defined in [Failure Message](#failure-message).
      * Check the counters for the values on the message:
        * If client profiles and prekey profiles are present on the message:
          * Checks that `K` corresponds to the number of concatenated client
            profiles. If it is not, aborts the DAKE and sends a
            "Failure Message", as defined in the
            [Failure Message](#failure-message) section.
          * Checks that `J` corresponds to the number of concatenated prekey
            profiles. If it is not, aborts the DAKE and sends a
            "Failure Message", as defined in the
            [Failure Message](#failure-message) section.
        * If and prekey messages are present on the message:
          * Checks that `N` corresponds to the number of concatenated prekey
            messages. If it is not, aborts the DAKE and sends a "Failure Message",
            as defined in [Failure Message](#failure-message).
      * Stores each client profile, prekey profile and prekey message if is
        possible in the Prekey Server's storage. If not, aborts the DAKE and
        sends a "Failure Message" as defined in the
        [Failure Message](#failure-message) section.
      * Sends a "Success Message", as defined in the
        [Success Message](#success-message) section.
   1. If this is a "Storage Information Request message":
      * Responds with a "Storage Status Message", as defined in
        the [Storage Status Message](#storage-status-message) section.

**Alice**

1. Receives a message from the Prekey Server:
   1. If this is a "Storage Status message":
      * Computes the `Status_MAC: KDF(0x10, prekey_mac_k || message type ||
        receiver's instance tag || stored prekey messages number, 64)`. Checks
        that it is equal to the one received in the Storage Status message.
        * If it is not, Alice ignores the message.
        * If it is, the number of stored prekey messages is displayed.
      * Securely deletes `prekey_mac_k`.
   1. If this is a "Success message":
      * Computes the `Success_MAC: KDF(0x12, prekey_mac_k || message type ||
        receiver's instance tag || "Success", 64)`. Checks that it
        is equal to the one received in the Sucess message.
        * If it is not, Alice ignores the message.
        * If it is, the human readable part of the message is displayed.
      * Securely deletes `prekey_mac_k`.
   1. If this is a "Failure message":
      * Computes the `Failure_MAC: KDF(0x13, prekey_mac_k || message type ||
        receiver's instance tag || "An error occurred", 64)`. Checks that it
        is equal to the one received in the Failure message.
        * If it is not, Alice ignores the message.
        * If it is, the human readable part of the message is displayed.
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
1. Generate a 4-byte instance tag to use as the sender's instance tag. Only
   generate it, if it hasn't been generated for the OTRv4 specification. If it
   has, use that one instead. If it hasn't, generate it, and use it for the OTRv4
   specification as well. Additional messages in this conversation will continue
   to use this tag as the sender's instance tag. Also, this tag is used to
   filter future received messages. Messages intended for this instance of the
   client will have this number as the receiver's instance tag.
1. Add the Client Profile previously generated.

To verify a DAKE-1 message:

1. Validate the Client Profile, as defined in
   [Validating a Client Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-user-profile)
   section of the OTRv4 specification.
1. Verify that the point `I` received is on curve Ed448. See
   [Verifying that a point is on the curve](https://github.com/otrv4/otrv4/blob/master/otrv4.md#verifying-that-a-point-is-on-the-curve)
   section of the OTRv4 specification for details.

A DAKE-1 message is an OTRv4 Prekey Server message encoded as:

```
Message type (BYTE)
  The message has type 0x01.

Sender's instance tag (INT)
  The instance tag of the client sending this message.

Sender's Client Profile (CLIENT-PROF)
  As described in the section "Creating a Client Profile" of the OTRv4
  specification.

I (POINT)
  The ephemeral public ECDH key.
```

### DAKE-2 Message

This is the second message of the DAKEZ. It is sent to commit to a choice of an
ECDH ephemeral key for the server, and to acknowledge the publisher's ECDH
ephemeral key. Before this acknowledgment, validation of the publisher's ECDH
key is done.

A valid DAKE-2 message is generated as follows:

1. Generate an ephemeral ECDH key pair, as defined in the
   [Generating ECDH and DH keys](https://github.com/otrv4/otrv4/blob/master/otrv4.md#generating-ecdh-and-dh-keys)
   section of the OTRv4 specification (ignore the generation of DH keys from
   this section):
   * secret key `s` (57 bytes).
   * public key `S`.
1. Compute
   `t = 0x00 || KDF(0x02, Alices_Client_Profile, 64) ||
    KDF(0x03, Prekey_Server_Composite_Indentity, 64) || I || S ||
    KDF(0x04, phi, 64)`.
   `phi` is the shared session state as mentioned in the
   [Shared Session State](#shared-session-state) section.
   `Prekey_Server_Composite_Identity` is the server identifier as mention in the
   [Prekey Server Composite Identity](#prekey-server-composite-identity) section.
1. Compute `sigma = RSig(H_s, sk_hs, {H_a, H_s, I}, t)`. See the
   [Ring Signature Authentication](https://github.com/otrv4/otrv4/blob/master/otrv4.md#ring-signature-authentication)
   section of the OTRv4 specification for details.
1. Use the sender's instance tag from the DAKE-1 message as the receiver's
   instance tag.

To verify a DAKE-2 message:

1. Check that the receiver's instance tag matches your instance tag.
1. Validate the Server Identifier by:
   * Calculating the fingerprint of the Server long-term public key (`H_s`).
   * Calculating the Server Identifier and compare with the one received.
1. Compute `t = 0x00 || KDF(0x02, Alices_Client_Profile, 64) ||
   KDF(0x03, Prekey_Server_Composite_Identity, 64) || I || S ||
   KDF(0x04, phi, 64)`.
   `phi` is the shared session state from the
   [Shared Session State](#shared-session-state) section.
   `Prekey_Server_Composite_Identity` is the server identifier from the
   [Prekey Server Composite Identity](#prekey-server-composite-identity)
   section.
1. Verify the `sigma` with `sigma == RVrf({H_a, H_s, I}, t)`. See the
   [Ring Signature Authentication](https://github.com/otrv4/otrv4/blob/master/otrv4.md#ring-signature-authentication)
   section of the OTRv4 specification for details.

A DAKE-2 message is an OTRv4 Prekey Server message encoded as:

```
Message type (BYTE)
  The message has type 0x02.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

Server Composite Identity (PREKEY-SERVER-COMP-ID)
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
   `t = 0x01 || KDF(0x05, Alices_Client_Profile, 64) ||
    KDF(0x06, Prekey_Server_Composite_Identity, 64) || I || S ||
    KDF(0x07, phi, 64)`.
   `phi` is the shared session state from
   [Shared Session State](#shared-session-state).
   `Prekey_Server_Composite_Identity` is the server identifier from the
   [Prekey Server Composite Identity](#prekey-server-composite-identity)
   section.
1. Compute `sigma = RSig(H_a, sk_ha, {H_a, H_s, S}, t)`, as defined in the
   [Ring Signature Authentication](https://github.com/otrv4/otrv4/blob/master/otrv4.md#ring-signature-authentication)
   section of the OTRv4 specification.
1. Continue to use the sender's instance tag.

To verify a DAKE-3 message:

1. Check that the receiver's instance tag matches your sender's instance tag.
1. Compute
   `t = 0x01 || KDF(0x05, Alices_Client_Profile, 64) ||
    KDF(0x06, Prekey_Server_Composite_Identity, 64) || I || S ||
    KDF(0x07, phi, 64)`.
   `phi` is the shared session state from
   [Shared Session State](#shared-session-state).
   `Prekey_Server_Composite_Identity` is the server identifier from the
   [Prekey Server Composite Identity](#prekey-server-identifier) section.
1. Verify the `sigma` with `sig == RVrf({H_s, H_a, S}, t)`. See the
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
    - Prekey Publication
    - Storage Information Request
```

### Prekey Publication Message

This is the message sent when you want to store/publish Prekey Ensembles to the
Prekey Server. This message can contain these three entities:

- Client Profiles
- Prekey Profiles
- Prekey Messages

Client Profiles and Prekey Profiles are included in this message when none have
been published before to the Prekey Server (this is the first time a client
uploads these values), when a new Client or Prekey Profile is generated with a
different long-term public key, and when the stored Client or Prekey Profile
will soon expire. A client must always upload new Client and Prekey Profiles
when one of these scenarios happen. A client does not delete the old values but
rather replace them on these scenarios. The maximum number of client profiles
and prekey profiles that can be published in one message is 255 respectively.

Prekey Messages are included in this message when there are few or none messages
left on the server. This can be checked by sending a "Storage Status Message" to
the Prekey Server. If the result of the "Storage Status Message" message
indicates that the number of stored Prekey Messages is getting low, the client
should upload more Prekey Messages - otherwise it will be impossible for other
clients to start non-interactive DAKE's with the client. The maximum number of
prekey messages that can be published in one message is 255.

This message must be attached to a DAKE-3 message.

A valid Prekey Publication Message is generated as follows:

1. Concatenate all Client Profiles, if they need to be published. Assign `K`
   as the number of Client Profiles.
1. Concatenate all Prekey Profiles, if they need to be published. Assign
   `J` as the number of Prekey Profiles.
1. Concatenate all the Prekey Messages. Assign `N` as the number of Prekey
   Messages.
1. Calculate the `Prekey MAC`:
   * If client profiles and Prekey profiles are present:
     `KDF(0x07, prekey_mac_k || message type || K || client profile || J ||
      prekey profiles || N || prekey messages, 64)`
   * If only Prekey Messages are present:
     `KDF(0x07, prekey_mac_k || message type || N || prekey messages, 64)`

The encoding looks like this:

```
Message type (BYTE)
  This message has type 0x04.

K (BYTE)
   The number of Client Profiles present in this message. This value is optional.

Client Profile (CLIENT-PROF)
  All 'K' Client Profiles created as described in the section "Creating a Client
  Profile" of the OTRv4 specification. This value is optional.

J (BYTE)
   The number of Prekey Profiles present in this message. This value is
   optional.

Prekey Profile (PREKEY-PROF)
  All 'J' Prekey Profiles created as described in the section "Creating a Prekey
  Profile" of the OTRv4 specification. This value is optional.

N (BYTE)
   The number of Prekey Messages present in this message.

Prekey Messages (DATA)
   All 'N' Prekey Messages serialized according to OTRv4 specification.

Prekey MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the Prekey Messages.
```

### Storage Information Request Message

This is the message sent when you want to know how many Prekey Messages there
are in storage. Only the publisher of those Prekey Messages will receive a
response to this message. This message must be attached to a DAKE-3 message.

The encoding looks like this:

```
Message type (BYTE)
  This message has type 0x05.
```

### Storage Status Message

The "Storage Status" message is sent by the Prekey Server in response to a
"Storage Information Request" message.

A valid "Storage Status" message is generated as follows:

1. Calculate the `Status MAC`:
   `KDF(0x10, prekey_mac_k || message type || receiver's instance tag ||
    Stored Prekey Messages Number, 64)`

It must be encoded as:

```
Message type (BYTE)
  The message has type 0x06.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

Stored prekey messages number (INT)
  The number of prekey messages stored in the prekey server for the
  long-term public key used during the DAKE.

Status MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the stored prekey messages number.
```

### Success Message

The success message is sent by the Prekey Server when an action (storing Prekey
Messages, for example) has been successful.

A valid Success message is generated as follows:

1. Calculate the `Success MAC`:
   `KDF(0x12, prekey_mac_k || message type || receiver's instance tag ||
    "Success", 64)`

It must be encoded as:

```
Message type (BYTE)
  The message has type 0x08.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

Success message (DATA)
  The human-readable details of this message. It contains the string "Success".

Success MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the Success message.
```

### Failure Message

The failure message is sent by the Prekey Server when an action (storing a
prekey message, for example) has not been successful. This can happen when the
Prekey Server storage is full.

A valid Failure message is generated as follows:

1. Calculate the `Failure MAC`:
   `KDF(0x13, prekey_mac_k || message type || receiver's instance tag ||
    "An error occurred", 64)`

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

* If server is in state IN_DAKE:

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
Prekey Publication Message           ------------->

                                     <-------------  Receives a DAKE-3 message and
                                                     stores the Client Profiles and
                                                     Prekey Profiles (if present),
                                                     and the Prekey Messages.
                                                     Sends a Success message.
```

Notice that this section refers to the ideal functionality of a Prekey Server.
Consider that a Prekey Server can, for example, decide to not perform some of
the verifications noted here.

By client we mean each device a user has.

1. Client creates Client Profiles, as defined in the OTRv4 specification. See
   the [Client Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#user-profile)
   section of the OTRv4 specification for details. It must create a Client Profile
   for each local long-term public key it has.
1. Client creates Prekey Profiles, as defined in OTRv4 specification. See
   the [Prekey Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-profile)
   section of the OTRv4 specification for details. It must create a Prekey
   Profile for each local long-term public key it has and sign the Prekey
   Profile with it.
1. Client creates Prekey Messages, as defined in OTRv4 specification. See
   the [Prekey message](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-message)
   section of the OTRv4 specification for details.
1. Client receives a Prekey Server Identity (e.g. prekey.autonomia.digital) and
   the Prekey Server long-term public key from a source. In XMPP, for example,
   this source is the server service discovery functionality.
1. Client authenticates (in a deniable way) with the server through the
   DAKE and, with that, it generates a shared secret.
   See section [Key Exchange](#key-exchange) for details.
1. Client sends Client Profiles and Prekey Profiles (if needed) for every
   long-term public key, and Prekey Messages to the Prekey Server, in the final
   message of the DAKE (DAKE-3 with a Prekey Publication Message attached). See
   the [Prekey Publication message](#prekey-publication-message) section for
   details.
1. Server verifies the received values:
   1. For every value, check the integrity.
   1. If Client and Prekey Profiles are present:
      1. Validate the Client Profiles as defined in the
         [Validating a Client Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-user-profile)
         section of the OTRv4 specification.
      1. Validate the Prekey Profiles as defined in the
         [Validating a Prekey Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-prekey-profile)
         section of the OTRv4 specification.
   1. If Prekey Messages are present:
      1. Validate the Prekey Messages as defined in the
         [Prekey Message](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-message)
         section of the OTRv4 specification.
   1. Discard any invalid or duplicated Prekey Messages.
1. Server stores the Prekey Messages associated with the identity.
1. Server sends an acknowledgment that the operation succeeded in the form of a
   "Success" message. See [Success Message](#success-message) for details.

## Retrieving Prekey Ensembles

```
Bob                                                  Prekey Server
----------------------------------------------------------------------------------------
Asks for Alice's identity             ------------->
(for example, alice@xmpp.org)

                                     <-------------  Sends Prekey Ensembles for
                                                     alice@xmpp.org

Receives Prekey Ensembles and
verifies them.
```

In order to send an encrypted offline message, a client must obtain a Prekey
Ensemble from the party they want to start a conversation with:

1. Client sends which identity and protocol versions it wants Prekey Ensembles
   for. It also adds from which device it's talking by specifying the instance
   tag.
1. Server checks if there are any Prekey Ensembles available for this identity.
   If there are none (or any of its values are missing), it sends a
   "No Prekey Ensembles available" message.
1. Server selects Prekey Ensembles for the requested version consisting of:
   * A valid Client Profile for every instance tag and long-term public key for
     the identity. That is, it selects different Client Profiles if they have the
     same instance tag but different long-term public keys. It always selects
     the Client Profiles with the latest expiry date.
   * A valid Prekey Profile for every instance tag and long-term public key for
     the identity. That is, different Prekey Profiles if they have the same
     instance tag but different long-term public keys. It always selects
     the Prekey Profiles with the latest expiry date.
   * One Prekey Message for every Client Profile and Prekey Profile selected.
     This Prekey Messages must have the same instance tag as the Client and
     Prekey Profiles.
   * Builds Prekey Ensembles with the selected values, for example:

     ```
     Identity || Client Profile (with instance tag 0x01, and long-term public key 1) ||
     Prekey Profile (with instance tag 0x01 and long-term public key 1) ||
     Prekey Message (with instance tag 0x01).

     Identity || Client Profile (with instance tag 0x01, and long-term public key 2) ||
     Prekey Profile (with instance tag 0x01 and long-term public key 2) ||
     Prekey Message (with instance tag 0x01).

     Identity || Client Profile (with instance tag 0x02, and long-term public key 3) ||
     Prekey Profile (with instance tag 0x02 and long-term public key 3) ||
     Prekey Message (with instance tag 0x02).
     ```

1. Server delivers all selected Prekey Ensembles to the Client in the form of
   a "Prekey Ensemble Retrieval" message. Uses the instance tag of the retriever
   as the "receiver's instance tag".
1. Server removes the selected Prekey Messages from its storage. It doesn't
   delete the Client or Prekey Profiles.
1. For each requested version, the Client receives the Prekey Ensembles and:
   1. Checks that there are 'L' number of Prekey Emsembles as stated in the
      "Prekey Ensemble Retrieval" message.
   1. Checks that there is at least one Client Profile, one Prekey Profile and
      one Prekey Message.
   1. Groups all Prekey Messages by instance tag. Subgroups the Client Profiles and
      Prekey Profiles from this group by the long-term public key.
   1. Validates all Prekey Ensembles:
      1. Checks that all the instance tags on the Prekey Ensemble's values are
         the same.
      1. [Validates the Client Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-user-profile).
      1. [Validates the Prekey Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-prekey-profile).
      1. Checks that the Prekey Profile is signed by the same long-term public
         key stated in it and in the Client Profile.
      1. Verifies the Prekey Message as stated in the
         [Prekey Message](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-message)
         section.
      1. Check that the OTR version of the Prekey Message matches one of the
         versions signed in the Client Profile contained in the Prekey Ensemble.
      1. Check if the Client Profile's version is supported by the client.
      1. Choose the Prekey Ensemble with the latest expiry time from each group.
   1. Discards any invalid or duplicated Prekey Ensembles.
1. Client chooses which Prekey Ensembles to send an encrypted offline message
   to:
   1. A client can optionally only use Prekey Ensembles that contain trusted
      long-term public keys.
   1. If there are several instance tags in the list of Prekey Ensembles, the
      client can optionally decide which instance tags to send messages to.
      Informs the user if the encrypted messages will be send to multiple
      instance tags (multiple devices).
   1. If there are multiple Prekey Ensembles per instance tag, decides whether
      to send multiple messages to the same instance tag.

### Prekey Ensemble Retrieval message

The encoding looks like this:

```
Message type (BYTE)
  The message has type 0x07.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

L (INT)
  The number of Prekey Ensembles

Ensembles (DATA)
  The concatenated Prekey Ensembles. Each Ensemble is encoded as:

   Client Profile (CLIENT-PROF)
   Prekey Profile (PREKEY-PROF)
   Prekey Message
      Prekey Messages are encoded as specified in OTRv4 specification, section
      'Prekey Message'.
```

### No Prekey Ensembles on Storage Message

This message is sent by the Prekey Server when it runs out of Prekey Messages,
or when it does not have a Client or Prekey profile.

The encoding looks like this:

```
Message type (BYTE)
  The message has type 0x08.

Receiver's instance tag (INT)
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

1. Client uses DAKEZ to authenticate with the server. See section
   [Key Exchange](#key-exchange) for details.
2. Server responds with a "Storage Status message" containing the number of
   Prekey Messages stored for the long-term public key, identity and instance
   tag used during the DAKEZ.

## A prekey server for OTRv4 over XMPP

This is an example of how a Prekey Server for the OTRv4 protocol will act over
XMPP. Note that a Prekey Server implementation for XMPP must support the
Service Discovery specification (XEP-0030, "disco").

### Discovering a Prekey Server

An entity can discover a Prekey Server by sending a Service Discovery items
("disco#items") request to the server of the entity it wants to look up
information for.

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
          category='otrv4-prekey-server'
          name='OTRv4 Prekey Server'
          type='text'/>
      <feature var='http://jabber.org/protocol/otrv4-prekey'/>
    </query>
  </iq>
```

### Publishing prekey values to the service

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

And the entity terminates the DAKE and sends the prekey values attached to the
last DAKE message:

```
  <message
      from='alice@xmpp.org/notebook'
      id='kud87ghduy'
      to='prekey.xmpp.org'>
    <body>?OTRPED...</body>
  </message>
```

And the server responds with a "Success" message:

```
  <message
      from='prekey.xmpp.org'
      id='0kdytsmslkd'
      to='alice@xmpp.org/notebook'>
    <body>?OTRPEF...</body> // TODO: check the type
  </message>
```

### Obtaining information about Prekey Messages from the service

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

And the entity terminates the DAKE and asks for storage information:

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

### Retrieving published prekeys from a prekey service

An entity asks the service for prekey messages from a particular party, for
example, `bob@xmpp.net`. Use the resourcePart of a JID to say which versions
you are interested on, for example "45" if you are interested on versions "4"
and "5".

```
  <message
      from='alice@xmpp.org/notebook'
      id='nzd143v8'
      to='prekey.xmpp.org'>
    <subject>bob@xmpp.net/45</subject>
  </message>
```

The service responds with a "Prekey Ensemble Retrieval" message if there are
prekey ensembles's values on storage:

```
  <message
      from='prekey.xmpp.org'
      id='13fd16378'
      to='alice@xmpp.org/notebook'>
    <subject>bob@xmpp.net/45</subject>
    <body>?OTRPL...</body>
  </message>
```

The service responds with a "No Prekey-Ensembles on Storage Message" if there
are no prekey ensembles's values on storage:

```
  <message
      from='prekey.xmpp.org'
      id='13fd16378'
      to='alice@xmpp.org/notebook'>
    <subject>bob@xmpp.net/45</subject>
    <body>?OTRPK...</body>
  </message>
```

## Detailed example of the prekey server over XMPP

`bob@xmpp.org` wants to know how many Prekeys Messages remain unused on the
Prekey Server:

1. `bob@xmpp.org` logs in to his server (`talk.xmpp.org`).
1. `bob@xmpp.org` uses service discovery to find a Prekey Server on his server
   (`prekey.xmpp.org`).
   1. The service discovery informs the Prekey Server's long-term public key.
1. `bob@xmpp.org` discovers the capabilities of `prekey.xmpp.org`.
   1. `prekey.xmpp.org` is capable of all features of the Prekey Server
       specification.
1. `bob@xmpp.org` asks `prekey.xmpp.org` about the number of prekeys messages
   it has stored for him:
   1. `bob@xmpp.org` deniable authenticates by using DAKEZ with
      `prekey.xmpp.org`.
   1. `bob@xmpp.org` sends a "Storage Status Message" attached to the last
       DAKEZ message to `prekey.xmpp.org`.
   1. `bob@xmpp.org` receives a "Storage Status Message" message depending from
      `prekey.xmpp.org`.

`bob@xmpp.org` wants to publish/store prekey messages in the Prekey Server:

1. `bob@xmpp.org` logs to his server (`talk.xmpp.org`).
1. `bob@xmpp.org` uses service discovery to find a Prekey Server on his server
   (`prekey.xmpp.org`).
   1. The service discovery also informs the Prekey Server's long-term public
      key.
1. `bob@xmpp.org` discovers the capabilities of `prekey.xmpp.org`.
   1. `prekey.xmpp.org` is capable of all features of a Prekey Server.
1. `bob@xmpp.org` wants to publish `prekey.xmpp.org` a client profile, a prekey
   profile and 5 prekey messages:
   1. `bob@xmpp.org` deniable authenticates by using DAKEZ with
      `prekey.xmpp.org`.
   1. `bob@xmpp.org` sends a "Prekey Publication Message" attached to the last
       DAKEZ message to `prekey.xmpp.org`.
   1. `bob@xmpp.org` receives a "Success" or "Failure" message depending if the
       above operation was successful or not from `prekey.xmpp.org`.

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
