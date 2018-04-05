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
publish and store user profiles, prekey profiles and prekey messages, and
retrieve prekey ensembles from an untrusted Prekey Server. A Prekey ensemble
contains the publisher's User Profile, the publisher's Prekey Profile and two
one-time use ephemeral public prekey values (denoted a prekey message), as
defined in the OTRv4 specification [\[1\]](#references). These prekey ensembles
are used for starting offline conversations.

OTRv4 specification defines a non-interactive DAKE, which is derived from the
XZDH protocol. This DAKE begins when Alice, who wants to initiate an offline
conversation with Bob, asks an untrusted Prekey Server for Bob's prekey
ensembles. The values for the prekeys ensembles have previously been stored in
the Prekey Server by a request from Bob.

This document aims to describe how the untrusted Prekey Server can be used to
securely publish, store and retrieve prekey ensembles and its values.

## Assumptions

OTRv4 Prekey Server specification does not fully protect against an active
attacker performing Denial of Service attacks (DoS).

During the DAKE performed by the publisher with the Prekey Server, the network
model provides in-order delivery of messages.

This specification aims to support future OTR versions. Because of that, the
Prekey Server should support multiple prekey messages from different/future
OTR versions, starting with the current version, 4.

## Security Properties

OTRv4 states the need for a service provider that stores key material used in
a deniable trust establishment for offline conversations. This service provider
is the Prekey Server, as establish in this specification.

There are three things that should be uploaded to the Prekey Server: signed user
profiles, signed prekey profiles and prekey messages. They are needed for
starting a non-interactive DAKE. Prekey profiles are needed as if only prekey
messages are used for starting non-interactive conversations, an active
adversary can modify the first flow from the publisher to use an adversarially
controlled ephemeral key, capture and drop the response from the retriever, and
then compromise the publisher's long-term secret key. The publisher will never
see the messages, and the adversary will be able to decrypt them. Moreover,
since long-term keys are usually meant to last for years, a long time may pass
between the retriever sending the messages and the adversary compromising the
publisher's long-term key. This attack is mitigated with the use of Prekey
Profiles that contain shared prekeys signed by the long-term secret key, and
that are reusable.

A set of prekey messages (with the one-time ephemeral secrets) is stored in the
Prekey Server to achieve forward secrecy. These prekey messages should be
immediately deleted after been retrieved.

The submissions of these values to the untrusted Prekey Server are deniably
authenticated by using DAKEZ. If they are not authenticated, then malicious
users can perform denial-of-service attacks (DoS). In order to preserve the
deniability properties of the whole OTRv4 protocol, they should be deniably
authenticated.

Furthermore, in order to safeguard the integrity of the submitted values to the
Prekey Server, a MAC of those values is used. The Prekey Server should check,
when receiving these values, for their integrity.

Note that the Prekey Server is untrusted and, therefore, can cause the
communication between to parties to fail. This can happen in several ways:

- The Prekey Server refuses to hand out Prekey Ensembles.
- The Prekey Server hands out incomplete Prekey Ensembles.
- The Prekey Server hands out expired values on the Prekey Ensembles.
- The Prekey Server can refuse to delete the prekey messages from it storage.
- The Prekey Server can say that "there are no prekey ensembles available" even
  if they are.
- The Prekey Server says a wrong number for how many values of the Prekey
  Ensemble there are on storage.

Furthermore, there can be a reduction in forward secrecy if one party
maliciously drains another party's prekey messages.

## Prekey Server Specifications

The Prekey Server used in this specification should be considered untrusted.
This means that a malicious server could cause communication between parties to
fail, as stated above.

The Prekey Server must have these capabilities:

- Receive user profiles, prekey profiles and a set of prekey messages, and store
  them by the corresponding identity. Inform that this operation have failed or
  has been successful.
- Deliver prekey ensembles previously stored.
- Inform the publisher about how many prekey messages are stored for them.
- Inform the retriever when there are no prekey ensembles (or any of its values)
  from an specific party.

The Prekey Server expects to only receive messages on the same network
authenticated clients use to exchange messages. This means that a message
received should be from the same network the publisher is believed to have
been authenticated to.

Although this specification defines an specific behavior from the Prekey Server
(e.g., by specifying that user profiles, prekey profiles and prekey messages
submissions should be validated by the Prekey Server), clients should not rely
on this prescribed behavior, as the Prekey Server is untrusted. It must be taken
into account that a misbehavior from the Prekey Server can potentially affect
the security of the whole OTRv4 protocol. For this reason, verifications must
be performed by clients as well, even though the Prekey Server should be
expected to perform them. Furthermore, clients working with a Prekey Server
are expected to upload new user profiles and prekey profiles when they get
expired or a new long-term public key is created.

Note that user profile, prekey profiles and prekey messages submissions to the
untrusted Prekey Server have to be authenticated. If they are not authenticated,
then malicious users can perform denial-of-service attacks. To preserve the
deniability of the overall OTRv4 protocol, prekeys messages should never be
digitally signed. The best approach is to authenticate prekey message uploads
using a DAKEZ exchange between the publisher and the Prekey Server, which
preserves deniability.

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
starting from version 4. This means that the Prekey Server will accept prekey
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

As previously stated, user profiles, prekey profiles and prekey messages
submissions to the Prekey Server have to be authenticated. If they are not
authenticated, then malicious users can perform denial-of-service attacks. To
preserve the deniability of the overall OTRv4 protocol, they are authenticated
using a DAKEZ [\[3\]](#references) exchange between the publisher and the Prekey
Server, which preserves deniability.

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
      the message and does not send anything further.
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
   1. If she wants to publish user profiles and prekey profiles, and/or prekey
      messages, she creates a "Prekey publication message", as defined in
      its [section](#prekey-publication-message).
   1. If she wants to ask for storage information, she creates a "Storage
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
   1. If this is a "Prekey Publication message":
      * Uses the sender's instance tag from the DAKE-3 message as the receiver's
        instance tag and checks that is equal to the previously seen.
      * Calculates the Prekey MAC key: `prekey_mac_k = KDF(0x08 || SK, 64)`.
      * Computes the `Prekey MAC`:
        * If user profiles and prekey profiles are present on the message:
          `KDF(0x07 || prekey_mac_k || message type || K || user profile || J
           || prekey profiles || N || prekey messages, 64)`.
        * If only prekey messages are present on the message:
          `KDF(0x07 || prekey_mac_k || message type || N || prekey messages, 64)`.
        * Checks that this `Prekey MAC` is equal to the one received in the
          "Prekey publication message". If it is not, the server aborts the DAKE
          and sends a "Failure Message", as defined in its
          [section](#failure-message).
      * Check the counters for the values on the message:
        * If user profiles and prekey profiles are present on the message:
          * Checks that `K` corresponds to the number of concatenated user
            profiles. If it is not, aborts the DAKE and sends a "Failure Message",
            as defined in its [section](#failure-message).
          * Checks that `J` corresponds to the number of concatenated prekey
            profiles. If it is not, aborts the DAKE and sends a "Failure Message",
            as defined in its [section](#failure-message).
        * If and prekey messages are present on the message:
          * Checks that `N` corresponds to the number of concatenated prekey
            messages. If it is not, aborts the DAKE and sends a "Failure Message",
            as defined in its [section](#failure-message).
      * Stores each user profile, prekey profile and prekey message if there is
        enough space in the Prekey Server's storage. If there is not, aborts the
        DAKE and sends a "Failure Message" as defined in its
        [section](#failure-message).
      * Sends a "Success Message", as defined in its [section](#success-message).
   1. If this is a "Storage Information Request message":
      * Responds with a "Storage Status Message", as defined in its
        [section](#storage-status-message).

**Alice**

1. Receives a message from the Prekey Server:
   1. If this is a "Storage Status message":
      * Computes the `Status_MAC: KDF(0x10 || prekey_mac_k || message type ||
        receiver's instance tag || stored prekey messages number, 64)`. Checks
        that it is equal to the one received in the Storage Status message.
        If it is not, Alice ignores the message.
   1. If this is a "Success message":
      * Computes the `Success_MAC: KDF(0x12 || prekey_mac_k || message type ||
        receiver's instance tag || "Success", 64)`. Checks that it
        is equal to the one received in the Sucess message. If it is
        not, Alice ignores the message.
   1. If this is a "Failure message":
      * Computes the `Failure_MAC: KDF(0x13 || prekey_mac_k || message type ||
        receiver's instance tag || "An error occurred", 64)`. Checks that it
        is equal to the one received in the Failure message. If it is
        not, Alice ignores the message.

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
    - Prekey Publication
    - Storage Information Request
```

### Prekey Publication Message

This is the message sent when you want to store/publish prekey ensembles to the
Prekey Server. This message can have three types of values to be published:

- User profiles
- Prekey profiles
- Prekey messages

User profiles and prekey profiles are included in this message when there are
none of these values on the Prekey Server (this is the first time a client
uploads these values), when a new User or Prekey Profile is generated with a
different long-term public key, and when the stored User or Prekey Profile is
expired. A client is mandated to always upload new User and Prekey Profiles when
one of these scenarios happen. A client does not delete the old values but
rather replace them on these scenarios.

Prekey messages are included in this message when there are none of this values
on the Prekey Server. This can be checked by sending a "Storage Status Message"
to the Prekey Server. If the client that received the "Storage Status Message"
checks that the storage of prekey message is getting low, it is mandated to
upload more prekey messages. The maximum number of prekey messages that can be
published at once is 255.

Notice that this message must be attached to a DAKE-3 message.

A valid Ensemble Publication message is generated as follows:

1. Concatenate all user profiles, if they are needed to be published. Assign `K`
   as the number of concatenated user profiles.
2. Concatenate all prekey profiles, if they are needed to be published. Assign
   `J` as the number of concatenated prekey profiles.
3. Concatenate all the prekey messages. Assign `N` as the number of concatenated
   prekey messages.
4. Calculate the `Ensemble MAC`:
   * If user profiles and prekey profiles are present:
     `KDF(0x07 || prekey_mac_k || message type || K || user profile || J ||
      prekey profiles || N || prekey messages, 64)`
   * If only prekey messages are present:
     `KDF(0x07 || prekey_mac_k || message type || N || prekey messages, 64)`

It must be encoded as:

```
Message type (BYTE)
  This message has type 0x04.

K (BYTE)
   The number of user profiles present in this message. This value is optional.

User Profile (USER-PROF)
  All 'K' user profiles created as described in the section "Creating a User
  Profile" of the OTRv4 specification. This value is optional.

J (BYTE)
   The number of prekey profiles present in this message. This value is
   optional.

Prekey Profile (PREKEY-PROF)
  All 'J' prekey profiles created as described in the section "Creating a User
  Profile" of the OTRv4 specification. This value is optional.

N (BYTE)
   The number of prekey messages present in this message.

Prekey messages (DATA)
   All 'N' prekey messages serialized according to OTRv4 specification.

Prekey MAC (MAC)
  The MAC with the appropriate MAC key of everything: from the message type to
  the prekey messages.
```

### Storage Information Request Message

This is the message sent when you want to know how many prekey messages are
there in storage. Only the publisher of those prekey messages can send this
message. This message must be attached to a DAKE-3 message.

It must be encoded as:

```
Message type (BYTE)
  This message has type 0x05.
```

### Storage Status Message

The "Storage Status" message is sent by the Prekey Server in response to a
"Storage Information Request" message.

A valid "Storage Status" message is generated as follows:

1. Calculate the `Status MAC`:
   `KDF(0x10 || prekey_mac_k || message type || receiver's instance tag ||
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

The success message is sent by the Prekey Server when an action (storing prekey
messages, for example) has been successful.

A valid Success message is generated as follows:

1. Calculate the `Success MAC`:
   `KDF(0x12 || prekey_mac_k || message type || receiver's instance tag ||
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
Prekey Server's storage is full.

A valid Failure message is generated as follows:

1. Calculate the `Failure MAC`:
   `KDF(0x12 || prekey_mac_k || message type || receiver's instance tag ||
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

This is the state machine for when a client wants to publish user profiles,
prekey profiles or prekey messages to the Prekey Server, or when it queries for
its status.

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
Prekey publication message           ------------->

                                     <-------------  Receives a DAKE-3 message and
                                                     stores the user profiles and
                                                     prekey profiles (if present),
                                                     and the prekey messages.
                                                     Sends a Success message.
```

Notice that this section refers to the ideal functionality of a Prekey Server.
Nevertheless, consider that an untrusted Prekey Server can, for example, not
perform some of the verifications here noted.

Note here that by client we mean each device a client has.

1. Client creates user profiles, as defined in OTRv4 specification. See
   the [User Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#user-profile)
   section of the OTRv4 specification for details. It must create a user profile
   for each local long-term public key it has.
1. Client creates prekey messages, as defined in OTRv4 specification. See
   the [Prekey message](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-profile)
   section of the OTRv4 specification for details. It must create a prekey
   profile for each local long-term public key it has and sign the prekey
   profile with it.
1. Client creates prekey messages, as defined in OTRv4 specification. See
   the [Prekey message](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-message)
   section of the OTRv4 specification for details.
1. Client receives a Prekey Server's identifier (e.g. prekey.autonomia.digital)
   and the Prekey Server's long-term public key from a source. In XMPP, for
   example, this source is the server's service discovery.
1. Client authenticates (in a deniable way) with the server through the
   interactive DAKE 'DAKEZ' and, with that, it generates a shared secret.
   See section [Interactive DAKE](#interactive-dake) for details.
1. Client sends user profiles and prekey profiles (if present), and prekey
   messages to the Prekey Server, in the last message of the
   DAKE (DAKE-3 with a Prekey publication message attached). It sends the
   available user and prekey profiles for every long-term public key it exists
   locally on the client/device (if needed), and a set of prekey messages.
   See the [Prekey Publication message](#prekey-publication-message) section
   for details.
1. Server verifies the received values:
   1. For every value, check the integrity.
   1. If user and prekey profiles are present:
      1. Validate the user profiles as defined on
         [Validating a User Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-user-profile)
         section of the OTRv4 specification.
      1. Validate the prekey profiles as defined on
         [Validating a Prekey Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-prekey-profile)
         section of the OTRv4 specification.
   1. If prekey messages are present:
      1. Validate the prekey messages as defined on
         [Prekey Message](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-message)
         section of the OTRv4 specification.
   1. Discard any invalid or duplicated prekey values.
1. Server stores the prekey messages associated with the identity.
1. Server sends an acknowledgment that the operation succeeded in the form of a
   "Success Message". See its [section](#success-message) for details.

## Retrieving Prekey Ensembles
```
Bob                                                  Prekey Server
----------------------------------------------------------------------------------------
Informs Alice's identity             ------------->
(for example, alice@xmpp.org)

                                     <-------------  Sends prekey ensembles for
                                                     alice@xmpp.org

Receives prekey ensembles and
verifies them.
```

In order to send an encrypted offline message, a client must obtain a prekey
ensemble from the party they are willing to start a conversation with:

1. Client informs which identity and protocol versions it wants prekey ensembles
   for. It also informs from which device its talking by specifying the instance
   tag.
1. Server checks if there are prekey ensembles on storage for this identity.
   If there are none (or one of its values is missing), it sends a
   "No Prekey Ensembles on Storage" message.
1. Server selects prekey ensembles for the requested version consisting of:
   * A valid user profile for every instance tag and long-term public key for
     the identity. That is, selects different user profiles if they have the
     same instance tag but different long-term public keys on it. Always selects
     the user profiles with the latest expiry date.
   * A valid prekey profile for every instance tag and long-term public key for
     the identity. That is, different prekey profiles if they have the same
     instance tag but different long-term public keys on it. Always selects
     the user profiles with the latest expiry date.
   * One prekey message for every user profile and prekey profile selected.
     This prekey messages should have the same instance tag as the user and
     prekey profiles.
   * Builds prekey ensembles with the selected values, for example:

     ```
     Identity || User Profile (with instance tag 0x01, and long-term public key 1) ||
     Prekey Profile (with instance tag 0x01 and long-term public key 1) ||
     prekey message (with instance tag 0x01).

     Identity || User Profile (with instance tag 0x01, and long-term public key 2) ||
     Prekey Profile (with instance tag 0x01 and long-term public key 2) ||
     prekey message (with instance tag 0x01).

     Identity || User Profile (with instance tag 0x02, and long-term public key 3) ||
     Prekey Profile (with instance tag 0x02 and long-term public key 3) ||
     prekey message (with instance tag 0x02).
     ```

1. Server delivers all selected prekey ensembles to the Client in the form of
   a "Prekey Ensemble Retrieval" message. Uses the instance tag of the retriever
   as the "receiver's instance tag".
1. Server removes the selected prekey messages from its storage. It does not
   delete neither the user nor prekey profiles.
1. For each requested version, the Client gets the prekey ensembles:
   1. Checks that there are 'L' number of prekey emsembles as stated on the
      "Prekey "Ensemble Retrieval" message.
   1. Checks that there is at least one user profile, one prekey profile and
      one prekey message.
   1. Groups all prekey values by instance tag. Subgroups the user profiles and
      prekey profiles from this group by the long-term public key, and groups
      them by that.
   1. Validates all prekey ensembles:
      1. Checks that all the instance tags on the Prekey Ensemble's values are
         the same.
      1. [Validates the User Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-user-profile).
      1. [Validates the Prekey Profile](https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-a-prekey-profile).
      1. Checks that the Prekey Profile is signed by the same long-term public
         key stated on it and on the User Profile.
      1. Verifies the Prekey message as stated on its
         [section](https://github.com/otrv4/otrv4/blob/master/otrv4.md#prekey-message).
      1. Check that the OTR version of the prekey message matches one of the
         versions signed in the User Profile contained in the Prekey Ensemble.
      1. Check if the User Profile's version is supported by the receiver.
      1. Choose the prekey ensemble with the latest expiry time from each group.
   1. Discards any invalid or duplicated prekey ensembles.
1. Client chooses which prekey ensembles to send an encrypted offline message
   to:
   1. A client can optionally only use prekey ensembles that contain trusted
      long-term public keys.
   1. If there are several instance tags in the list of prekey ensembles, the
      client can optionally decide which instance tags to send messages to.
      Informs the user if the encrypted messages will be send to multiple
      instance tags (multiple devices).
   1. If there are multiple prekey ensembles per instance tag, decides whether
      to send multiple messages to the same instance tag.

### Prekey Ensemble Retrieval message

It must be encoded as:

```
Message type (BYTE)
  The message has type 0x07.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

L (INT)
  The number of prekey ensembles

Ensembles (DATA)
  The concatenated prekey ensembles. Each ensemble is encoded as:

   User Profile (USER-PROF)
   A Prekey Profile (PREKEY-PROF)
   Prekey message
      Prekey messages are encoded as specified in OTRv4 specification, section
      'Prekey message'.
```

### No Prekey Ensembles on Storage Message

This message is sent by the Prekey Server when it runs out of prekey messages,
or when it does not have a user or prekey profile (there are none on storage).

It must be encoded as:

```
Message type (BYTE)
  The message has type 0x08.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

No Prekey-Messages message (DATA)
  The human-readable details of this message. It contains the string "No prekey
  messages available for this identity".
```

## Query the server for its storage status

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
   [Interactive DAKE](#interactive-dake) for details.
2. Server responds with a "Storage Status message" containing the number of
   prekey messages stored for the long-term public key, identity and instance
   tag used during the DAKEZ.

## A prekey server for OTRv4 over XMPP

This is an example of how a Prekey Server for the OTRv4 protocol will act over
XMPP. Note that a Prekey Server's implementation over XMPP must support the
Service Discovery specification (XEP-0030, "disco").

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

### Obtaining information about prekey messages from the service

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

#### Retrieving published prekeys from a prekey service

An entity asks the service for prekey messages from a particular party, for
example, "bob@xmpp.net". Use the resourcePart of a JID to say which versions
you are interested on, for example "45" if you are interested on verisons "4"
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

`bob@xmpp.org` wants to know how many prekeys messages remain unused on the
Prekey Server:

1. bob@xmpp.org logs in to his server (`talk.xmpp.org`).
1. bob@xmpp.org uses service discovery to find a Prekey Server on his server
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
1. `bob@xmpp.org` wants to publish `prekey.xmpp.org` a user profile, a prekey
   profile and 5 prekey messages:
   1. `bob@xmpp.org` deniable authenticates by using DAKEZ with
      `prekey.xmpp.org`.
   1. `bob@xmpp.org` sends a "Prekey Publication Message" attached to the last
       DAKEZ message to `prekey.xmpp.org`.
   1. `bob@xmpp.org` receives a "Success" or "Failure" message depending if the
       above operation was successful or not from `prekey.xmpp.org`.

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
