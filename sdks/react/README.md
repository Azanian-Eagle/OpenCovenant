# @azanian-eagle/opencovenant-react

[![NPM Version](https://img.shields.io/npm/v/@azanian-eagle/opencovenant-react.svg)](https://www.npmjs.com/package/@azanian-eagle/opencovenant-react)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE)

Turnkey React hooks and components for sovereign compliance verification powered by **OpenCovenant** and **Vela**.

## 🇿🇦 Overview

Building upon Azanian Eagle's `opensentinel-react` playbook, `@azanian-eagle/opencovenant-react` brings statutory consent, taint boundaries, and minor zero-retention controls directly to the modern React component hierarchy.

## Installation

```bash
npm install @azanian-eagle/opencovenant-react @azanian-eagle/opencovenant-client
```

## Usage

```tsx
import React, { useState } from "react";
import { useCovenantGuard } from "@azanian-eagle/opencovenant-react";

export function StudentChatBox() {
  const [prompt, setPrompt] = useState("");
  const { isCompliant, sanitizeAndSubmit, error } = useCovenantGuard({
    covenant: "SocraticTutorEgress",
    enforceMinorZeroRetention: true,
  });

  const handleSubmit = async () => {
    await sanitizeAndSubmit({
      curriculum_prompt: prompt,
      age_years: 14,
    });
  };

  return (
    <div>
      <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} />
      <button onClick={handleSubmit} disabled={!isCompliant}>
        Submit Sovereign Prompt
      </button>
      {error && <span style={{ color: "red" }}>{error.message}</span>}
    </div>
  );
}
```

## Features

* **Local-First Sanitisation**: Redacts and salts sensitive PII client-side before submission.
* **POPIA Section 35 Enforcement**: Rejects persistence of minor conversations automatically.
* **React 18 & 19 Ready**: Full support for React Server Components (RSC) and Suspense.

## Licence

Licensed under either Apache License, Version 2.0 or MIT license.
