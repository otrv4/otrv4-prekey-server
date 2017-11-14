# OTRv4 Prekey Server

```
Disclaimer

This protocol specification is a draft.
```

OTRv4 Prekey Server provides an specification for otrv4 [\[1\]](#references)
protocol when it needs an untrusted central server to store prekey messages.

## Overview

## Server specifications

The server can store otrv4 prekey messages which a party can later retrieve.
The server can inform when the store of prekey messages is getting low. If the
prekey server cannot return any prekey messages, the non-interactive DAKE from
otrv4 must wait until one can be obtained.

## Publishing Prekey Messages

// TODO: should prekey messages have an expiration time included in their
encoding?

An OTRv4 client must generate a user's prekey messages and publish them to the prekey server. Implementers are expected to create their own policy dictating how often their clients upload prekey messages to the prekey server. Prekey messages expire when their user profile expires. Thus new prekey messages should be published to the prekey server before they expire to keep valid prekey messages available. In addition, one Prekey message should be published for every long term key that belongs to a user. This means that if Bob uploads 3 long term keys for OTRv4 to his client, Bob's client must publish 3 prekey messages.

If prekey submissions are not authenticated, then malicious users can perform
denial-of-service attacks. To preserve the deniability of the overall otrv4
protocol, one-time prekey messages should never be digitally signed. The best
approach is to authenticate prekey message uploads using a DAKEZ exchange
between the uploader and the server, which preserves deniability. As an added
safeguard, the server can require a ZKPK of the private keys associated with
the prekeys.

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

## Retrieving Prekey Messages

// TODO: how to do this query?

1. Party requests a prekey message from server by asking for it from an
   specific party x.
2. Server replies with prekey message. // TODO: deletes this prekey or waits
   for its expiration?

### References

1. *OTR version 4*. Available at:
   https://github.com/otrv4/otrv4/blob/master/otrv4.md