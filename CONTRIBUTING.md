# Contributing to useMeter

Thank you for your interest in contributing to useMeter! This document outlines the development workflow, architecture guidelines, and standards for contributions.

## Development Setup

useMeter requires [Bun](https://bun.sh) (v1.4+). Node.js and npm/pnpm/yarn are not used.

```sh
# Clone the repository
git clone https://github.com/muwat0/useMeter.git
cd useMeter

# Install dependencies
bun install

# Start local development server with hot-reload
bun run dev

# Run strict typecheck and test suite
bun x tsc --noEmit
bun test

# Build client production bundle
bun run build
```

## Adding a New Provider Adapter

useMeter consolidates balances, credits, and quotas across AI providers via a clean adapter contract:

1. **Implement `ProviderAdapter`** in `src/core/providers/<provider-name>.ts`:
   - Implement `supports(provider: string): boolean` with intentional, deliberate provider identifiers.
   - Implement `fetchUsage(ctx: FetchContext, credential: StoredCredential): Promise<UsageReport>`.
   - Never log, commit, or expose plaintext secrets, bearer tokens, or raw provider payloads.
   - Map vendor responses to normalized domain types from `src/types.ts` (`UsageReport`, `UsageLimit`, `UsageAmount`).
2. **Register the adapter** in `src/core/providers/registry.ts`.
3. **Add unit tests** in `tests/<provider-name>-provider.test.ts` using typed fixtures and synthetic `ctx.fetch` mocks.

## Code Conventions

- **Strict TypeScript:** No `any`, preserve `noUnusedLocals`, `noUnusedParameters`, and `noFallthroughCasesInSwitch`.
- **Domain Contracts:** Canonical types belong in `src/types.ts` (`UsageUnit`, `UsageStatus`, `UsageReport`). Do not leak provider-specific wire schemas outside their respective adapters.
- **Security First:**
  - Sensitive credentials must go through `StorageVault` (AES-256-GCM encryption).
  - Never commit API keys, tokens, `.env` files, or local database snapshots.
- **Testing:**
  - Always run `bun x tsc --noEmit` and `bun test` before opening a pull request.
  - All unit and integration tests must pass cleanly (0 failures).

## Pull Request Guidelines

1. Fork the repository and create a feature branch (`git checkout -b feature/my-provider`).
2. Follow [Conventional Commits](https://www.conventionalcommits.org) for commit messages (e.g. `feat(provider): add Together AI quota adapter`).
3. Ensure all tests pass and TypeScript emits zero errors.
4. Open a pull request against `main` describing the changes, motivation, and test coverage.
