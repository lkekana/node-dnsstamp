## @lkekana/dnsstamp

`@lkekana/dnsstamp` is a fork of [dnsstamp](https://github.com/rs/node-dnsstamp) updated for a modern Javascript environment & with Martin Heidegger ([@martinheidegger](https://github.com/martinheidegger))'s contributions merged. See his [fork](https://github.com/martinheidegger/node-dnsstamp) / [PR](https://github.com/rs/node-dnsstamp/pull/1)

# DNS Stamp

This node module provides a simple API to parse and generate [DNS Stamp](https://dnscrypt.info/stamps-specifications/) as defined by [Frank Denis](https://twitter.com/jedisct1).

## Installation

```sh
npm install @lkekana/dnsstamp
```

## Usage

Parse a stamp URL:

```typescript
import { DNSStamp } from "@lkekana/dnsstamp";

const stamp = DNSStamp.parse("sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20");
console.log(stamp.toString());
```

Create a stamp URL:

```typescript
import { DNSStamp } from "@lkekana/dnsstamp";

const dnsCryptStamp = new DNSStamp.DNSCrypt("1.1.1.1", {
  pk: "...",
  providerName: "example.com",
});
console.log(dnsCryptStamp.toString());
```

Supported stamps:

* `DNSStamp.DNSCrypt`: constructor(`addr`, {`props`, `pk`, `providerName`})
* `DNSStamp.DOH`: constructor(`addr`, {`props`, `hostName`, `hash`, `path`})
* `DNSStamp.DOT`: constructor(`addr`, {`props`, `hostName`, `hash`})
* `DNSStamp.Plain`: constructor(`addr`, {`props`})

## Licenses

All source code is licensed under the [MIT License](https://raw.github.com/rs/node-dnsstamp/master/LICENSE).
