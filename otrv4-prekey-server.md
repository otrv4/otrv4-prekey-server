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
prekey messages). It may also refuse to hand out prekey messages.

## Overview

![Diagram](./img/diagram.svg)

## Server specifications

The server must have two main capabilities:

- Receive prekey messages
- Deliver prekey messages

## Publishing Prekey Messages

1. Client creates prekey messages.
1. Client authenticates with the server through interactive DAKE and obtain shared secret.
1. Client sends prekey messages encrypted with the shared secret.
1. Server verifies received prekey messages[\[2\]](#references).
1. Server stores prekey message.
1. Server sends acknowledgment that the operation succeeded.

TODO: do the prekey messages need to be sent encrypted (inside a data message)?
If so, should the server reveal MAC keys?
Would this be part of this spec or would it be part of a spec specifc to a communication protocol (XMPP, SMS, Skype)?

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
   1. Filter out expired prekey messages from each group.
   1. Choose the prekey message with the latest expiry time from each group.
1. Client choses which prekey messages to send an encrypted offline message to.
   1. Inform the user if the message will be send to multiple instance tags and/or long-term keys.
   1. Decide if multiple conversations should be kept simultaneously (one per instance tag).

TODO: should the server simply send multiple prekey messages to the requester
and terminate the connection when it is done, or should there be any metadata
about the request (total items = X, current item = Y, item = prekey message)?
TODO: deduplicate information when sending back multiple one-time prekeys,
i.e. if 100 prekeys get returned, don't say "version 4" 100 times


===== Previous content =====

1. Party connects to server.
2. Party requests a prekey message from server by asking for it from an
   specific party x and with an specific id. This party must have the other
   party user profile.
3. Server replies with prekey message. This prekey message is removed from
   storage. Never handle out the same prekey twice. Client should
   also not accept it.

The server should provide one of the parties prekey message if one exists, and
then delete it. If all of parties prekey messages on the server have been
deleted, then nothing is returned.

// TODO: should an error by return in this case?

Upon receiving of the prekey message, the party verifies the user profile. It
aborts the protocol if it fails.

// TODO: should there be: identifiers stating which of Bob's prekeys Alice
used?

// TODO: check the attacks: replay, key reused, attacker modifies prekey or
format?

// TODO: include the analysis

The server must have this characteristics:

- The server should delivery a prekey message per non-expired user profile to
  the client that requested it.

- The server should not delivery a prekey message twice.

- The server should not log who is publishing the prekeys messages.

//TODO: should we mention how to manage the server long term keys?
//TODO: is it a problem if server tell client how many prekeys remains?  Do we
have any risk in the case when an user tries to impersonate other one during
DAKEZ?

- The server should return a default message to the client when it has no
  prekey messages.

- The server should implement ways to prevent malicious prekey messages drain
  (e.g rate limit).


## Attacks

- What if the server delivers all the prekey messages to an adversary

## References

1. https://github.com/otrv4/otrv4/blob/master/otrv4.md
2. https://github.com/otrv4/otrv4/blob/master/otrv4.md#validating-prekey-messages
3. http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf
   https://github.com/WhisperSystems/Signal-Server/wiki/API-Protocol
