# OTRv4 Prekey Server

```
Disclaimer

This protocol specification is a draft.
```

OTRv4 Prekey Server provides an specification for OTRv4 [\[1\]](#references)
protocol when it needs an untrusted central server to store user profiles and
prekey messages.

// TODO: should we remove shared prekey from user profile and to create a
specific profile, like prekey profile? Shared prekey is only used for
non-interactive case

OTRv4 is designed for asynchronous communication where one user ("Bob") is
offline but has published some information to a server. This is information,
for OTRv4, are called "prekey messages". Another user ("Alice") wants to use
that information to send encrypted data to Bob, and also establish a shared
secret key. This specification aims to explain how to securely do this process.

This server should be considered untrusted. This means that a malicious server
could cause communication between parties to fail (e.g. by refusing to deliver
prekey messages).  It may also refuse to hand out prekey messages.

## Overview

![Diagram](./img/diagram.svg)

## Server specifications

The server must have this characteristics:

- The server should be able to receive prekey messages from a client in an
  authenticated and deniable way[\[2\]](#references).

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

## Preliminaries

Both parties involved (Bob and Server) already have their long-term keys
created. This long-term key pair is a Ed448 key pair.

Parties involved in an OTRv4 conversation have public shared prekeys
(`ED448-SHARED-PREKEY`) which are signed as part of the user profile signing
process and expired when the user profile expires.

They also have a set of one-time prekey messages, which are each used in a
single non-interactive DAKE run. They are named as so because they are
essentially protocol messages which a party publishes to the server prior to
the other party been able to send non-interactive messages.

Parties must generate an user profile and publish it. A user profile contains
the Ed448 long term public key, a shared prekey for offline conversations,
information about supported versions, a profile expiration date, a signature of
all these, and an optional transition signature.

```
Profile Expiration (PROF-EXP):
  8 byte signed value, big-endian

User Profile (USER-PROF):
  Ed448 public key (ED448-PUBKEY)
  Versions (DATA)
  Profile Expiration (PROF-EXP)
  Public Shared Prekey (ED448-SHARED-PREKEY)
    The shared prekey used between different prekey messages.
  Profile Signature (EDDSA-SIG)
  (optional) Transitional Signature (SIG)
```

Parties need to publish this user profile once and renew it once it is expired
(thus, replacing the old one). On the contrary, parties can publish prekey
messages to the server as much as they want (e.g. when the server informs that
the server's store of one-time prekey messages is getting low).

// TODO: check this below paragraph

// TODO: this can be something to look at in out-of-order

After uploading a new signed user profile, Bob may keep the private key
corresponding to the previous public shared prekey around for some period of
time, to handle messages using it that have been delayed in transit.
Eventually, the party should delete this private key for forward secrecy.

## Publishing Prekey Messages

// TODO: should prekey messages have an expiration time included in their
encoding?

// TODO: do the prekey messages expire or only the shared prekey?

An OTRv4 client must generate a user's prekey messages and publish them to the
prekey server. Implementers are expected to create their own policy dictating
how often their clients upload prekey messages to the prekey server. Prekey
messages expire when their user profile expires. Thus new prekey messages
should be published to the prekey server before they expire to keep valid
prekey messages available. In addition, one prekey message should be published
for every long term key that belongs to a user. This means that if Bob uploads
3 long term keys for OTRv4 to his client, Bob's client must publish at least 3
prekey messages.

// TODO: correctly define the ZKPK

If prekey submissions are not authenticated, then malicious users can perform
denial-of-service attacks. To preserve the deniability of the overall OTRv4
protocol, one-time prekey messages should never be digitally signed. The best
approach is to authenticate prekey message uploads using a DAKEZ exchange
between the uploader and the server, which preserves deniability. As an added
safeguard, the server can require a ZKPK of the private keys associated with
the prekeys.

// TODO: who does this request happen?

1. Party requests to start a DAKE with server with DAKEZ.
2. Server receives this query and replies with an identity message.
3. Party receives and validates the identity message. Replies with an auth-r
   message.
4. Server receives and validates the auth-r message. Replies with an auth-i
   message.
5. Party receives and validates the auth-i message. Replies with prekey message
   to be stored.
6. Server stores prekey message. // TODO: sends acknowledgment that it has
   stored?

Signal creates this at install time: one signed prekey and x unsigned prekeys.

Can be:
- Client generates the shared prekey.
- Client creates a user profile with the shared prekey and the long term key.
- User profile gets published
- Party requests to create a prekey message with the shared prekey.// TODO: can
  the key be reused?
- Party does a DAKEZ with server and uploads prekey message with and ID.

## Retrieving Prekey Messages

// TODO: how many prekeys messages arrive?

// TODO: how to do this query?

// TODO: deduplicate information when sending back multiple one-time prekeys,
i.e. if 100 prekeys get returned, don't say "version 4" 100 times

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

## Attacks

- What if the server delivers all the prekey messages to an adversary

## References

1. https://github.com/otrv4/otrv4/blob/master/otrv4.md
2.   http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf
   https://github.com/WhisperSystems/Signal-Server/wiki/API-Protocol
