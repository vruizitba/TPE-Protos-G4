# Management Protocol

## 1. Transport

The management protocol runs over TCP on the management listener configured by
the server. The default endpoint is `127.0.0.1:8080`.

The protocol is line-oriented text. A request is one UTF-8 compatible ASCII
line terminated by `LF` (`\n`). Clients may send `CRLF`; servers ignore the
optional `CR`. Pipelining is not supported: a client sends one command and
waits for its response before sending another command.

Responses are also line-oriented. Successful responses start with `+OK`.
Failed responses start with `-ERR`. Multi-field responses use spaces inside a
single line. Lists are serialized as comma-separated values or `-` when empty.

## 2. Authentication

The `AUTH` command authenticates a management session:

```text
AUTH <secret>
```

After three invalid authentication attempts in the same session, the server
locks the session and rejects further commands. A locked session can be closed
with `QUIT`.

If the server was started without an admin secret, commands that require
authentication fail with `-ERR auth required`.

## 3. Commands

All commands except `AUTH` and `QUIT` require a successful `AUTH`.

```text
STATS
```

Returns operational counters:

```text
+OK conn-accepted=<n> conn-active=<n> conn-rejected=<n> auth-fail=<n> origin-ok=<n> origin-fail=<n> bytes-c2o=<n> bytes-o2c=<n> admin-sessions=<n>
```

```text
USERS
```

Returns SOCKS usernames. Passwords are never returned.

```text
+OK users=<name>,<name>
```

If there are no users:

```text
+OK users=-
```

```text
USER SET <name> <password>
```

Adds or replaces a SOCKS user.

```text
USER DELETE <name>
```

Deletes a SOCKS user.

```text
CONFIG GET
```

Returns the mutable runtime configuration:

```text
+OK negotiation-timeout=<n> connect-timeout=<n> idle-timeout=<n> max-connections=<n>
```

```text
CONFIG SET <key> <value>
```

Changes a non-negative integer configuration value. Valid keys are:
`negotiation-timeout`, `connect-timeout`, `idle-timeout`, and
`max-connections`.

```text
QUIT
```

Closes the management session.

## 4. Error Responses

The server returns `-ERR` for malformed commands, unknown commands, missing
arguments, invalid numeric values, unknown configuration keys, authentication
failures, locked sessions, and unavailable shared state.
