# OTRv4 Prekey Server

```
Disclaimer

This protocol specification is a draft.
```

OTRv4 Prekey Server provides an specification for OTRv4 [\[1\]](#references)
protocol when it needs an untrusted central server to store prekey messages.

In order to perform a non-interactive DAKE the user who wants to initiate the
conversation needs to obtain prekey messages from a prekey server.

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
- There should be prekey messages for every long-term public key that a device
  has.

Check this: https://github.com/otrv4/otrv4/blob/master/architecture-decisions/009-non-interactive-dake.md#publishing-and-retrieving-prekey-messages-from-a-prekey-server

## Overview

TODO: change the diagram to explain the new DAKE with details. (Work in Progress)

## Server specifications

The server must have three capabilities:

- Receive prekey messages and store them.
- Deliver prekey messages previously stored.
- Inform the publisher about how many prekey messages are stored for them.

The server expects to only receive messages on the same network authenticated
clients use to exchange messages, that is, if a message is received from the
network the sender is believed to be authenticated by the network.

TODO: The server needs to store prekey messages from multiple OTR versions.
TODO: When a prekey message is requested, there must be a way to say ALL the
versions you are interested in.
TODO: When a prekey message is received from the server, check if it has the
version you requested.

## Publishing Prekey Messages

#### High-level overview

![Publishing prekey messages](./img/publish-prekey.svg)

1. Client creates prekey messages.
   1. Prekey messages are created as defined in OTRv4 spec.
1. Client receives server identifier (e.g. prekey.autonomia.digital) and the
   server's long-term public key from some source.
1. Client authenticates with the server through interactive DAKE and, by that,
   generates a shared secret.
1. Client sends prekey messages to Server.
1. Server verifies received prekey messages.
   1. Check user profile (and if it is signed by the same long-term key that
      was used in the DAKE).
   1. Check everything the OTRv4 spec mandates in regard to prekey messages
      [\[2\]](#references).
1. Server stores prekey message.
1. Server sends acknowledgment that the operation succeeded.


#### Detailed protocol

The following parameters are expected to be generated beforehand:

* `(I, g*I)`: Alice's long-term keypair. See: OTRv4, section
   "Public keys, Shared Prekeyes and Fingerprints".
* `(R, g*R)`: Server's long-term keypair. See: OTRv4, section
   "Public keys, Shared Prekeyes and Fingerprints".
* `A`: Alice's User-Profile. See: OTRv4, section "Creating a User Profile".
* `S`: the Server's profile.

Alice is also expected to receive the server's identity and its long-term
public key so they can be manually verified by her.

The protocol goes as follows:

**Alice**

1. Selects ephemeral keypair `(i, g*i)`. See: OTRv4 spec, section "Generating
   ECDH and DH keys".
1. Sends `(A, g*i)` to the server.

**Server**

1. Verify the received message. If something fails, abort the DAKE.
   1. Verify if `g*i` is on curve Ed448. See: OTRv4 spec, section "Generating
      ECDH and DH keys".
   1. Verify if `A` is a valid not-expired profile. See: OTRv4 spec, section
      "Validating a User Profile".
1. Obtain `g*I` from `A`. See: OTRv4 section, "User profile".
1. Selects ephemeral keypair `(r, g*r)`. See: OTRv4 spec, section "Generating
   ECDH and DH keys".
1. Computes `phi`.
1. Computes `t = “0” ∥ KDF(0x02 ∥ A) ∥ KDF(0x03 ∥ S) ∥ g*i ∥ g*r ∥ KDF(0x04 ∥ phi)`.
1. Computes `sig = RSig(g*R, R, {g*I, g*R, g*i}, t)`. See: OTRv4 section "Ring Signature Authentication".
1. Computes `k = KDF(0x01 ∥ (g*i)*r)` and securely erases `r`.
1. Send `(S, g*r, sig)`.

**Alice**

1. Verify if the server's identity and long-term public key match. Abort the DAKE if they don't.
1. Verify the received message. If something fails, abort the DAKE.
   1. Verify if `g*r` is on curve Ed448. See: OTRv4 spec, section
      "Generating ECDH and DH keys".
   1. Verify if `S` is a valid server profile. (TODO: How?)
   1. Computes `phi`.
   1. Computes `t = “0” ∥ KDF(0x02 ∥ A) ∥ KDF(0x03 ∥ S) ∥ g*i ∥ g*r ∥ KDF(0x04 ∥ phi)`.
   1. Verify if `sig == RVrf({g*I, g*R, g*i}, t)`. See: OTRv4 section "Ring Signature Authentication".
1. Computes `k = KDF(0x01 ∥ (g*r)*i)` and securely erases `i`.
1. Compute `t = "1" ∥ KDF(0x05 ∥ A) ∥ KDF(0x6 ∥ S) ∥ g*i ∥ g*r ∥ KDF(0x07 ∥ phi)`.
1. Computes `sig = RSig(g*I, I, {g*I, g*R, g*r}, t)`.
1. Computes `MAC = KDF(0x08 ∥ prekey messages)`.
1. Send `(sig, prekey messages, MAC)`.

**Server**

1. Verify the received message. If something fails, abort the DAKE and send a
   failure message.
   1. Compute `t = "1" ∥ KDF(0x05 ∥ A) ∥ KDF(0x06 ∥ S) ∥ g*i ∥ g*r ∥ KDF(0x07 ∥ phi)`.
   1. Verify if `sig == RVrf({g*I, g*R, g*r}, t)`. See: OTRv4 section "Ring Signature Authentication".
1. Verify if the integrity of the prekey messages.
1. Verify the received prekey messages. See: OTRv4, section "Receiving Prekey Messages".
1. Store the received prekey messages.

For `g`, see OTRv4, section "Elliptic Curve Parameters".

The operator `||` represents concatenation of a byte array. Their operands must
be serialized into byte arrays. Serialization of points in an elliptic curve is
definer in OTRv4 spec, section "Encoding and Decoding".

**KDF**

The key derivation function is defined as:

```
KDF(value) = SHAKE-256("OTRv4-Prekey-Server" || value, 64)

Unlike SHAKE standard, output size (d) here is defined in bytes. You may need to convert it to bits.

```

**Phi**

For an explanation about `phi`, see OTRv4, section "Shared Session State".
For a prekey server that receive requests over XMPP, this must be:


```
phi = sender's bare JID || receiver's bare JID
```

For example:

```
phi = "alice@jabber.net" || "prekeys.xmpp.org"
```

**Server Profile**

For a prekey server that uses XMPP, this must be the prekey server's bare JID (for example, prekey.xmpp.org) and its fingerprint. Example:

```
profile = "prekey.xmpp.org" || "E5lZcvcEhw7NE8OLDjIWwzRIT2hfaPyg04yARNC9zDitkuVvsBtgkddHjBCyXP99YGtgXgP+aOU="
```

**Encoding**

A DAKE-1 message must be serialized as:

```
Message type (BYTE)
  The message has type 0x01.

Sender's instance tag (INT)
  The instance tag of the person sending this message.

Receiver's instance tag (INT)
  The instance tag of the intended recipient. As the instance tag is used to
  differentiate the clients that a participant uses, this will often be 0 since
  the other party may not have set its instance tag yet.

Sender's User Profile (USER-PROF)
  As described in the section "Creating a User Profile".

g*i (POINT)
  The ephemeral public ECDH key.

```

A DAKE-2 message must be serialized as:


```
Message type (BYTE)
  The message has type 0x02.

Sender's instance tag (INT)
  The instance tag of the person sending this message.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

Sender's Server Profile (USER-PROF)
  As described in the section "Creating a User Profile".

g*r (POINT)
  The ephemeral public ECDH key.

sigma (RING-SIG)
  The 'RING-SIG' proof of authentication value.

```

A DAKE-3 message must be serialized as:

```
Message type (BYTE)
  The message has type 0x03.

Sender's instance tag (INT)
  The instance tag of the person sending this message.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

sigma (RING-SIG)
  The 'RING-SIG' proof of authentication value.

Action (BYTE)
  0x01 for publishing prekey messages
  0x02 for querying the server about the server's storage

If Action is 0x01

N (SHORT)
   The number of prekey messages present in this message.

PREKEYS (BYTES)
   All (N) prekey messages serialized according to OTRv4 spec.

MAC (BYTES)
   The MAC for the field PREKEYS.

If Action is 0x02

Nothing else.

```

A storage status message must be serialized as:

```
Message type (BYTE)
  The message has type 0x04.

Sender's instance tag (INT)
  The instance tag of the person sending this message.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

Stored prekey messages (INT)
  The number of prekey messages stored in the server for the
  long-term public key used in the DAKE.
```

After serializing, encode in Base-64, then prepend `?OTRP` and add fragmentation
like in OTRv4.

**State machine**

TODO: explain each "event", state and transitions.
TODO: Failure scenarios (no prekey for the identity, for example).

Server receives DAKE-msg-1: ...

Server receives DAKE-msg-3: ...

Otherwise: ...

## Retrieving Prekey Messages

### High-level overview

![Retrieving prekey messages](./img/retrieve-prekey.svg)

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

1. Client uses a DAKEZ to authenticate with the server.
2. Server responds with number of prekey messages stored for the long-term
   public key and identity used on the DAKEZ.

### Interactive DAKE

TODO: is it the same DAKE as the one used to publish? Is there a different state machine?
If the dake has 2 different kinds of msg-3, we need to say which one is valid here and there.

## A prekey server for OTRv4 over XMPP

A prekey server implementation MUST support Service Discovery (XEP-0030) ("disco").

##### Discovering a prekey service

An entity often discovers a prekey service by sending a Service Discovery items ("disco#items") request to its own server.

```
<iq from='alice@xmpp.org/notebook'
    id='h7ns81g'
    to='xmpp.org'
    type='get'>
  <query xmlns='http://jabber.org/protocol/disco#items'/>
</iq>
```

The server then returns the services that are associated with it.

```
<iq from='xmpp.org'
    id='h7ns81g'
    to='alice@xmpp.org/notebook'
    type='result'>
  <query xmlns='http://jabber.org/protocol/disco#items'>
    <item jid='prekey.xmpp.org'
          name='OTRv4 prekey server'/>
  </query>
</iq>
```

#### Discovering the features supported by a prekey service

An entity may wish to discover if a service implements the prekey server protocol;
in order to do so, it sends a service discovery information ("disco#info") query
to the prekey service's JID.

```
<iq from='alice@xmpp.org/notebook'
    id='lx09df27'
    to='prekey.xmpp.org'
    type='get'>
  <query xmlns='http://jabber.org/protocol/disco#info'/>
</iq>
```

The service MUST return its identity and the features it supports.

```
<iq from='prekey.xmpp.org'
    id='lx09df27'
    to='alice@xmpp.org/notebook'
    type='result'>
  <query xmlns='http://jabber.org/protocol/disco#info'>
    <identity
        category='otrv4-prekey'
        name='OTRv4 prekey server'
        type='text'/>
    <feature var='http://jabber.org/protocol/otrv4-prekey'/>
  </query>
</iq>
```

#### Publishing prekeys to the service

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

And the entity terminates the DAKE and send the prekey messages
(DAKE-3 message has action 0x01):

```
<message
    from='alice@xmpp.org/notebook'
    id='kud87ghduy'
    to='prekey.xmpp.org'>
  <body>?OTRPED...</body>
</message>
```

And the server respond with a success message:
TODO: Should this message also have instance tags?

```
<message
    from='prekey.xmpp.org'
    id='0kdytsmslkd'
    to='alice@xmpp.org/notebook'>
  <body>?OTRP OK</body>
</message>
```

#### Obtaining information about your prekeys from the service

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

And the entity terminates the DAKE and asks for storage information
(DAKE-3 message has action 0x02):

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

TODO.




bob@xmpp.org wants to know how many prekeys remain unused on the server

1. bob@xmpp.org logs in to his server (talk.xmpp.org).
1. bob@xmpp.org uses service discovery to find a prekey server on his server
   (prekey.xmpp.org).
   1. The service discovery also informs the prekey server's long-term public
      key.
1. bob@xmpp.org discovers the capabilities of prekey.xmpp.org.
   1. prekey.xmpp.org is capable of all features of a prekey server.
1. bob@xmpp.org asks prekey.xmpp.org about the number of prekeys it has stored
   for him.
   1. TODO: Explain the DAKE.

bob@xmpp.org wants to publish prekey messages

1. bob@xmpp.org logs to his server (talk.xmpp.org).
1. bob@xmpp.org uses service discovery to find a prekey server on his server
   (prekey.xmpp.org).
   1. The service discovery also informs the prekey server's long-term public
      key.
1. bob@xmpp.org discovers the capabilities of prekey.xmpp.org.
   1. prekey.xmpp.org is capable of all features of a prekey server.
1. bob@xmpp.org generates 3 prekeys:
   1. prekey1: instance tag 90
   1. prekey2: instance tag 90
   1. prekey3: instance tag 90
1. bob@xmpp.org sends DAKE-msg1 to prekey.xmpp.org.
   1. TODO: details of how ephemeral keys will be generated.
1. bob@xmpp.org receives DAKE-msg2 from prekey.xmpp.org/123980831. (The resource
   identifies this DAKE).
   1. TODO: details of how ephemeral keys will be generated.
   1. bob@xmpp.org verifies prekey.xmpp.org long-term public key.
1. bob@xmpp.org sends DAKE-msg3 to prekey.xmpp.org/123980831.
   1. TODO: details of how to attach prekeys to the DAKE-msg3.
   1. DAKE-msg3 also contains prekey1, prekey2, prekey3.
1. bob@xmpp.org receives a SUCCESS/FAILURE msg from prekey.xmpp.org/123980831.

alice@jabber.org wants to send an offline message to bob@xmpp.org

1. alice@jabber.org logs to his server (xmpp.jabber.org).
1. alice@jabber.org uses service discovery to find a prekey server on bob's
   server (prekey.xmpp.org).
   1. The service discovery also informs the prekey server's long-term public
      key.
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
      1. The received prekey messages are from different instance tags, no need
         to choose by latest expiration time.
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
