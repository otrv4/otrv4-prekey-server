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

TODO: change the diagram to explain the new DAKE with details.

![Diagram](./img/diagram.svg)

## Server specifications

The server must have three capabilities:

- Receive prekey messages and store them.
- Deliver prekey messages previously stored.
- Inform the publisher about how many prekey messages are stored for they.

The server expects to only receive messages on the same network authenticated
clients use to exchange messages, that is, if a message is received from the
network the sender is believed to be authenticated by the network.
TODO: Does this break deniability for publishing? And for retrieving?

## Publishing Prekey Messages

1. Client creates prekey messages.
   1. Prekey messages are created as defined in OTRv4 spec.
1. Client receives server identifier (e.g. prekey.autonomia.digital) and the long-term public key from some source.
1. Client authenticates with the server through interactive DAKE and obtain shared secret.
   1. Client sends DAKE-msg1.
      1. TODO: Explain.
   1. Server sends DAKE-msg2.
      1. TODO: Explain.
   1. Client sends DAKE-msg3 + prekey messages.
      1. TODO: Explain.
      1. Use shared secret as a MAC key.
   1. Server verifies received prekey messages.
      1. Check user profile (and if it is signed by the same long-term key that was used on the DAKE).
      1. Check everything the OTRv4 spec mandates in regard to prekey message [\[2\]](#references).
1. Server stores prekey message.
1. Server sends acknowledgment that the operation succeeded.

## Retrieving Prekey Messages

In order to send an encrypted offline message a client must obtain a prekey
messages:

1. Client informs which identity it wants a prekey message for.
1. Server selects one prekey message for each instance tag of the identity.
   1. Group all prekey messages by instance tag.
   1. Filter out expired prekey messages from each group.
   1. Choose one prekey message from each group.
   1. TODO: Add examples.
1. Server delivers all selected prekey messages to the Client.
1. Server removes the selected prekey messages from its storage.
1. Client selects the latest prekey messages form each instance tag.
   1. Group all prekey messages by instance tag.
   1. Filter out invalid prekey messages (expired, for example) from each group.
   1. Choose the prekey message with the latest expiry time from each group.
   1. TODO: Add examples.
1. Client choses which prekey messages to send an encrypted offline message to.
   1. Inform the user if the message will be send to multiple instance tags and/or long-term keys.
   1. Decide if multiple conversations should be kept simultaneously (one per instance tag).

TODO: Failure scenarios (no prekey for the identity, for example). Should a failure be specific (with error codes, for example)?

TODO: should the server simply send multiple prekey messages to the requester
and terminate the connection when it is done, or should there be any metadata
about the request (total items = X, current item = Y, item = prekey message)?
TODO: deduplicate information when sending back multiple one-time prekeys,
i.e. if 100 prekeys get returned, don't say "version 4" 100 times

## Query the server for its storage status

1. Client uses a DAKE-Z to authenticate to the server.
   1. TODO: Add details about the DAKE.
2. Server responds with number of prekey messages stored for the long-term public key and identity used on the DAKE-Z.


// TODO: should there be: identifiers stating which of Bob's prekeys Alice
used?

## Attacks

// TODO: check the attacks: replay, key reused, attacker modifies prekey or
format?

- What if the server delivers all the prekey messages to an adversary

## References

1. https://github.com/otrv4/otrv4/blob/master/otrv4.md
2. https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-prekey-messages
3. http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf
   https://github.com/WhisperSystems/Signal-Server/wiki/API-Protocol
