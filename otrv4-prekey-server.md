# OTRv4 Prekey Server

```
Disclaimer

This protocol specification is a draft.
```

OTRv4 Prekey Server provides an specification for OTRv4 [\[1\]](#references)
protocol when it needs an untrusted central server to store and prekey messages.

In order to perform a non-interactive DAKE the user who initiates the
communication needs to obtain prekey messages from a prekey server.

This document aims to describe how the prekey server can be used to securely
publish and retrieve already published prekey messages.

This server should be considered untrusted. This means that a malicious server
could cause communication between parties to fail (e.g. by refusing to deliver
prekey messages).

### From meeting

- The prekey server will need some OTRv4-specific prekey server software, so this
  software can easily generate ephemeral keys for each connection.
- The prekey server must have some identifier to be used for the DAKE, maybe the
  domain name.
- A prekey message can be encrypted in the server but when handled out to the
  receiver it should be decrypted.
- This specification should define how a client asks for prekey messages:
  is it going to be a sort of query-message-like message?
- There should be prekey messages for every long-term public key that a device
  has.

Check this: https://github.com/otrv4/otrv4/blob/master/architecture-decisions/009-non-interactive-dake.md#publishing-and-retrieving-prekey-messages-from-a-prekey-server

## Overview

TODO: change the diagram to explain the new DAKE with details. (Work in Progress)

![Diagram](./img/publish-prekey.svg)

## Server specifications

The server must have three capabilities:

- Receive prekey messages and store them.
- Deliver prekey messages previously stored.
- Inform the publisher about how many prekey messages are stored for they.

The server expects to only receive messages on the same network authenticated
clients use to exchange messages, that is, if a message is received from the
network the sender is believed to be authenticated by the network.

## Publishing Prekey Messages

#### High-level overview

1. Client creates prekey messages.
   1. Prekey messages are created as defined in OTRv4 spec.
1. Client receives server identifier (e.g. prekey.autonomia.digital) and the long-term public key from some source.
1. Client authenticates with the server through interactive DAKE and obtain shared secret.
1. Client sends prekey messages to Server.
1. Server verifies received prekey messages.
   1. Check user profile (and if it is signed by the same long-term key that was used on the DAKE).
   1. Check everything the OTRv4 spec mandates in regard to prekey message [\[2\]](#references).
1. Server stores prekey message.
1. Server sends acknowledgment that the operation succeeded.

#### Detailed protocol

The following parameters are expected to be generated beforehand:

* `(x, g*x)`: Alice's long-term keypair. See: OTRv4, section "Public keys, Shared Prekeyes and Fingerprints".
* `(y, g*y)`: Server's long-term keypair. See: OTRv4, section "Public keys, Shared Prekeyes and Fingerprints".
* `A`: Alice's User-Profile. See: OTRv4, section "Creating a User Profile".
* `S`: the Server's profilei. (TODO: Define how this is generated. Probably its identity - prekey.xmpp.org - and its long-term key's fingerprint).

Alice is also expected to receive the server's identity and its long-term
public key so they can be manually verified by her.

The protocol goes as follows:

**Alice**

1. Selects ephemeral keypair `(i, g*i)`. See: OTRv4 spec, section "Generating ECDH and DH keys".
1. Sends `(A, g*i)` to the server.

**Server**

1. Verify the received message. If something fails, abort the DAKE.
   1. Verify if `g*i` is on curve Ed448. See: OTRv4 spec, section "Generating ECDH and DH keys".
   1. Verify if `A` is a valid not-expired profile. See: OTRv4 spec, section "Validating a User Profile".
1. Obtain `g*I` from `A`. See: OTRv4 section, "User profile".
1. Selects ephemeral keypair `(r, g*r)`. See: OTRv4 spec, section "Generating ECDH and DH keys".
1. Computes `phi`.
1. Computes `t = “0” ∥ KDF_1(0x06 ∥ A, 64) ∥ KDF_1(0x07 ∥ S, 64) ∥ g*i ∥ g*r ∥ KDF_1(0x08 ∥ phi)`.
1. Computes `sig = RSig(g*y, y, {g*x, g*y, g*i}, t)`. See: OTRv4 section "Ring Signature Authentication".
1. Computes `k = KDF_1(0x04 ∥ (g*i)*r)` and securely erases `r`.
1. Send `(S, g*r, sig)`.

**Alice**

1. Verify if the server's identity and long-term public key match. Abort the DAKE if they don't.
1. Verify the received message. If something fails, abort the DAKE.
   1. Verify if `g*r` is on curve Ed448. See: OTRv4 spec, section "Generating ECDH and DH keys".
   1. Verify if `S` is a valid server profile. (TODO: How?)
   1. Computes `phi`.
   1. Computes `t = “0” ∥ KDF_1(0x06 ∥ A, 64) ∥ KDF_1(0x07 ∥ S, 64) ∥ g*i ∥ g*r ∥ KDF_1(0x08 ∥ phi)`.
   1. Verify if `sig == RVrf({g*x, g*y, g*i}, t)`. See: OTRv4 section "Ring Signature Authentication".
1. Computes `k = KDF_1(0x04 ∥ (g*r)*i)` and securely erases `i`.
1. Compute `t = "1" ∥ KDF_1(0x09 ∥ A, 64) ∥ KDF_1(0x10 ∥ S, 64) ∥ g*i ∥ g*r ∥ KDF_1(0x11 ∥ phi)`.
1. Computes `sig = RSig(g*x, x, {g*x, g*y, g*r}, t)`.
1. Send `(sig, prekey messages, prekey messages MAC)`. (TODO: how to calculate the MAC).

**Server**

1. Verify the received message. If something fails, abort the DAKE and send a failure message.
   1. Compute `t = "1" ∥ KDF_1(0x09 ∥ A, 64) ∥ KDF_1(0x10 ∥ S, 64) ∥ g*i ∥ g*r ∥ KDF_1(0x11 ∥ phi)`.
   1. Verify if `sig == RVrf({g*x, g*y, g*r}, t)`. See: OTRv4 section "Ring Signature Authentication".
1. Verify if the integrity of the prekey messages.
1. Verify the received prekey messages. See: OTRv4, section "Receiving Prekey Messages".
1. Store the received prekey messages.

For `phi`, see OTRv4, section "Shared Session State".
For `KDF_1`, see OTRv4, section "Key Derivation Functions".
For `g`, see OTRv4, section "Elliptic Curve Parameters".

**State machine**

TODO: explain each "event", state and transitions.
TODO: Failure scenarios (no prekey for the identity, for example).

Server receives DAKE-msg-1: ...

Server receives DAKE-msg-3: ...

Otherwise: ...

## Retrieving Prekey Messages

In order to send an encrypted offline message a client must obtain a prekey
messages:

1. Client informs which identity it wants a prekey message for.
1. Server selects one prekey message for each instance tag of the identity.
   1. Group all prekey messages by instance tag.
   1. Filter out expired prekey messages from each group.
   1. Choose one prekey message from each group.
1. Server delivers all selected prekey messages to the Client.
1. Server removes the selected prekey messages from its storage.
1. Client selects the latest prekey messages form each instance tag.
   1. Group all prekey messages by instance tag.
   1. Filter out invalid prekey messages (expired, for example) from each group.
   1. Choose the prekey message with the latest expiry time from each group.
1. Client choses which prekey messages to send an encrypted offline message to.
   1. Inform the user if the message will be send to multiple instance tags and/or long-term keys.
   1. Decide if multiple conversations should be kept simultaneously (one per instance tag).

## Query the server for its storage status

1. Client uses a DAKE-Z to authenticate to the server.
2. Server responds with number of prekey messages stored for the long-term public key and identity used on the DAKE-Z.

### Interactive DAKE

TODO: is it the same DAKE as the one used to publish? Is there a different state machine?
If the dake has 2 different kinds of msg-3, we need to say which one is valid here and there.

## XMPP example

bob@xmpp.org wants to know how many prekeys remain unused on the server

1. bob@xmpp.org logs in to his server (talk.xmpp.org).
1. bob@xmpp.org uses service discovery to find a prekey server on his server (prekey.xmpp.org).
   1. The service discovery also informs the prekey server's long-term public key.
1. bob@xmpp.org discovers the capabilities of prekey.xmpp.org.
   1. prekey.xmpp.org is capable of all features of a prekey server.
1. bob@xmpp.org asks prekey.xmpp.org about the number of prekeys it has stored for him.
   1. TODO: Explain the DAKE.

bob@xmpp.org wants to publish prekey messages

1. bob@xmpp.org logs to his server (talk.xmpp.org).
1. bob@xmpp.org uses service discovery to find a prekey server on his server (prekey.xmpp.org).
   1. The service discovery also informs the prekey server's long-term public key.
1. bob@xmpp.org discovers the capabilities of prekey.xmpp.org.
   1. prekey.xmpp.org is capable of all features of a prekey server.
1. bob@xmpp.org generates 3 prekeys:
   1. prekey1: instance tag 90
   1. prekey2: instance tag 90
   1. prekey3: instance tag 90
1. bob@xmpp.org sends DAKE-msg1 to prekey.xmpp.org.
   1. TODO: details of how ephemeral keys will be generated.
1. bob@xmpp.org receives DAKE-msg2 from prekey.xmpp.org/123980831. (The resource identifies this DAKE).
   1. TODO: details of how ephemeral keys will be generated.
   1. bob@xmpp.org verifies prekey.xmpp.org long-term public key.
1. bob@xmpp.org sends DAKE-msg3 to prekey.xmpp.org/123980831.
   1. TODO: details of how to attach prekeys to the DAKE-msg3.
   1. DAKE-msg3 also contains prekey1, prekey2, prekey3.
1. bob@xmpp.org receives a SUCCESS/FAILURE msg from prekey.xmpp.org/123980831.

alice@jabber.org wants to send an offline message to bob@xmpp.org

1. alice@jabber.org logs to his server (xmpp.jabber.org).
1. alice@jabber.org uses service discovery to find a prekey server on bob's server (prekey.xmpp.org).
   1. The service discovery also informs the prekey server's long-term public key.
1. alice@jabber.org discovers the capabilities of prekey.xmpp.org.
   1. prekey.xmpp.org is capable of all features of a prekey server.
1. alice@jabber.org asks prekey.xmpp.org for prekeys from bob@xmpp.org.
1. prekey.xmpp.org delivers 3 prekeys to her:
   1. Server has the following prekey messages stored for bob@xmpp.org
      1. prekey1: instance tag 90. Expired.
      1. prekey2: instance tag 90. Not expired.
      1. prekey3: instance tag 91. Not expired.
      1. prekey4: instance tag 91. Not expired.
   1. Server chooses to deliver the following instance tags to alice@jabber.org
      1. prekey2: instance tag 90. Not expired.
      1. prekey3: instance tag 91. Not expired.
1. alice@jabber.org choses which prekey messages to use.
   1. Validate received prekey messages.
      1. The received prekey messages are not expired.
      1. The received prekey messages are from different instance tags, no need to choose by latest expiration time.
   1. Client asks the user if they want to send one message to each instance tag.
      1. If user says: "yes", send one message to each instance tag.
      1. If user says: "no", send one message to the instance tag chosen by the user.
1. alice@jabber.org sends an offline encrypted message to bob@xmpp.org.

## Attacks

// TODO: check the attacks: replay, key reused, attacker modifies prekey or
format?

- What if the server delivers all the prekey messages to an adversary

## References

1. https://github.com/otrv4/otrv4/blob/master/otrv4.md
2. https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-prekey-messages
3. http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf
   https://github.com/WhisperSystems/Signal-Server/wiki/API-Protocol
