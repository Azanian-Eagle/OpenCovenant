# @azanian-eagle/opencovenant-client

[![NPM Version](https://img.shields.io/npm/v/@azanian-eagle/opencovenant-client.svg)](https://www.npmjs.com/package/@azanian-eagle/opencovenant-client)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE)

Official TypeScript and JavaScript client SDK for **OpenCovenant** and **The Vela Programming Language (`.vela`)**.

## 🇿🇦 Overview

`@azanian-eagle/opencovenant-client` enables web, mobile, and Node.js applications to interface seamlessly with data-sovereign Vela covenants. It ensures that runtime payloads honour POPIA (South Africa), GDPR (EU), and CCPA (California) invariants before network transmission.

## Installation

```bash
npm install @azanian-eagle/opencovenant-client
# or
pnpm add @azanian-eagle/opencovenant-client
# or
bun add @azanian-eagle/opencovenant-client
```

## Quickstart

```typescript
import { verify_SocraticTutorEgress, type LearnerSessionPayload } from "./generated/opencovenant_client";

const payload: LearnerSessionPayload = {
  learner_sa_id: "0401015800085",
  guardian_email: "parent@example.co.za",
  age_years: 15,
  curriculum_prompt: "Please explain quadratic equations in Grade 10 Maths.",
  session_nonce: "018f3a5b-6b2a-7e3f-91cb-a03d159be432",
};

// Validate that payload satisfies statutory invariants
const verification = verify_SocraticTutorEgress(payload);
console.log("Verified by:", verification.verifiedBy);
```

## Features

* **Zero Runtime Overhead**: Thin immutable wrappers emitted directly by `velac build`.
* **Zero PII Leaks**: Full compile-time awareness of ephemeral client-only properties (`ttl = 0s`).
* **Framework Agnostic**: Works out of the box with Next.js, Vite, Node.js, Bun, and React Native.

## Licence

Licensed under either Apache License, Version 2.0 or MIT license.
