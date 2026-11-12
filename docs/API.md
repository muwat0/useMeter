# useMeter External V1 API & Personal Access Tokens (PAT)

useMeter provides a versioned, read-heavy HTTP API (`/api/v1/*`) allowing external tools, desktop widgets (Waybar, Polybar, tmux), terminal status lines, and automation scripts to access your consolidated AI usage, balances, and quotas without relying on browser cookies.

---

## 1. Authentication & Personal Access Tokens (PAT)

All external API endpoints authenticate using standard HTTP Bearer tokens:

```http
Authorization: Bearer um_pat_<hex_token>
```

### Generating a Token
1. Sign in to your useMeter dashboard (`https://usemeter.example.com`).
2. Click the **Settings (⚙️)** button in the top navigation bar.
3. Scroll to the **API & External Access (Personal Access Tokens)** section.
4. Enter a descriptive token name (e.g., `Laptop Waybar`, `CLI Script`).
5. Choose an expiration policy:
   - **30 Days**
   - **90 Days** (default)
   - **1 Year**
   - **No Expiration**
6. Click **Generate New Token**.
7. **Copy your token immediately.** For security, useMeter reveals the raw token (`um_pat_...`) **only once** upon creation.

### Token Security & Lifecycle
- **Format:** `um_pat_` prefix followed by 64 hex characters (32 cryptographically secure random bytes; 71 characters total).
- **At-Rest Storage:** Raw tokens are never stored in the database. Only the SHA-256 hash (`token_hash`) and an 18-character masked prefix (e.g., `um_pat_0f1d...9441`) are persisted.
- **Tenant Isolation:** Tokens are strictly bound to the issuing user's identity. Foreign credentials, reports, and administrative resources are never disclosed.
- **Quota Limit:** Maximum 25 active tokens per user account.
- **Revocation:** Tokens can be instantly revoked from the Settings modal or via `DELETE /api/tokens/:id`. Any script using a revoked token receives `401 Unauthorized`.
- **Cascade Deletion:** If a user account is deleted, all associated personal access tokens are automatically removed.

---

## 2. API Endpoints

### 2.1. Compact Summary — `GET /api/v1/summary`

Designed for status bars, Waybar, Polybar, tmux, and shell prompts where a lightweight overview is required without parsing nested provider quotas.

- **Method:** `GET`
- **Headers:** `Authorization: Bearer <token>`
- **Rate Limit:** 120 requests/minute (`RATE_LIMIT_POLICIES.apiRead`)

#### Example Request
```sh
curl -sS -H "Authorization: Bearer um_pat_..." \
  https://usemeter.example.com/api/v1/summary
```

#### Example Response (HTTP 200)
```json
{
  "success": true,
  "timestamp": 1729000000000,
  "user": {
    "email": "user@example.com",
    "role": "user"
  },
  "totals": {
    "activeAccounts": 3,
    "totalBalanceUsd": 45.50,
    "totalSpentUsd": 12.30,
    "healthyCount": 3,
    "staleCount": 0,
    "errorCount": 0
  },
  "accounts": [
    {
      "credentialId": "cred-uuid-1",
      "provider": "openrouter",
      "accountLabel": "Personal OpenRouter",
      "health": "healthy",
      "balanceUsd": 20.00,
      "spentUsd": 4.25,
      "limitsCount": 2,
      "fetchedAt": 1729000000000,
      "error": null
    },
    {
      "credentialId": "cred-uuid-2",
      "provider": "openai-codex",
      "accountLabel": "Work ChatGPT",
      "health": "healthy",
      "balanceUsd": null,
      "spentUsd": null,
      "limitsCount": 2,
      "fetchedAt": 1729000000000,
      "error": null
    }
  ]
}
```

---

### 2.2. Full Normalized Usage Reports — `GET /api/v1/usage`

Returns the complete list of normalized usage reports across all connected accounts belonging to the authenticated user. Secrets, refresh tokens, and internal wire formats are stripped.

- **Method:** `GET`
- **Headers:** `Authorization: Bearer <token>`
- **Rate Limit:** 120 requests/minute (`RATE_LIMIT_POLICIES.apiRead`)

#### Example Request
```sh
curl -sS -H "Authorization: Bearer um_pat_..." \
  https://usemeter.example.com/api/v1/usage
```

#### Example Response (HTTP 200)
```json
{
  "success": true,
  "timestamp": 1729000000000,
  "data": [
    {
      "provider": "openrouter",
      "credentialId": "cred-uuid-1",
      "accountLabel": "Personal OpenRouter",
      "fetchedAt": 1729000000000,
      "limits": [
        {
          "id": "account_balance",
          "label": "Account Net Balance",
          "amount": {
            "used": 0,
            "remaining": 20.00,
            "limit": 20.00,
            "unit": "usd"
          },
          "status": "ok"
        },
        {
          "id": "key_usage",
          "label": "API Key Spending",
          "amount": {
            "used": 4.25,
            "unit": "usd"
          },
          "status": "ok"
        }
      ],
      "health": "healthy",
      "stale": false,
      "source": "live",
      "accent": "amber",
      "createdAt": 1728000000000
    }
  ]
}
```

---

### 2.3. On-Demand Polling Trigger — `POST /api/v1/poll`

Triggers a background refresh across all accounts belonging to the authenticated user and returns updated reports.

- **Method:** `POST`
- **Headers:** `Authorization: Bearer <token>`
- **Rate Limit:** 1 request every 30 seconds (`RATE_LIMIT_POLICIES.manualPoll`)

#### Example Request
```sh
curl -sS -X POST -H "Authorization: Bearer um_pat_..." \
  https://usemeter.example.com/api/v1/poll
```

#### Response (HTTP 200)
```json
{
  "success": true,
  "count": 3,
  "data": [ ...updated reports... ]
}
```

If triggered too frequently, returns `429 Too Many Requests` with a `Retry-After` header.

---

### 2.4. Token Management Endpoints

These endpoints manage your Personal Access Tokens. They accept either an existing web session cookie or a Bearer token.

#### List Tokens — `GET /api/tokens`
```sh
curl -sS -H "Authorization: Bearer um_pat_..." https://usemeter.example.com/api/tokens
```
```json
{
  "success": true,
  "tokens": [
    {
      "id": "pat-uuid-1",
      "name": "Waybar Widget",
      "tokenPrefix": "um_pat_0f1d...9441",
      "createdAt": 1729000000000,
      "lastUsedAt": 1729000500000,
      "expiresAt": 1736784000000
    }
  ]
}
```

#### Create Token — `POST /api/tokens`
- Payload: `{"name": "Laptop CLI", "expiresInDays": 90}` (`expiresInDays` is optional; omit or pass `null` for no expiration).
```sh
curl -sS -X POST \
  -H "Cookie: usage_session=..." \
  -H "Content-Type: application/json" \
  -d '{"name":"Laptop CLI","expiresInDays":90}' \
  https://usemeter.example.com/api/tokens
```
```json
{
  "success": true,
  "token": {
    "id": "pat-uuid-2",
    "name": "Laptop CLI",
    "tokenPrefix": "um_pat_e8a2...3b1f",
    "createdAt": 1729000000000,
    "lastUsedAt": null,
    "expiresAt": 1736784000000
  },
  "rawToken": "um_pat_e8a245c091f82d41b072e..."
}
```

#### Revoke Token — `DELETE /api/tokens/:id`
```sh
curl -sS -X DELETE \
  -H "Authorization: Bearer um_pat_..." \
  https://usemeter.example.com/api/tokens/pat-uuid-2
```
```json
{
  "success": true
}
```

---

## 3. Desktop & Script Integration Recipes

### 3.1. Waybar (Hyprland / Sway)

Add a custom module to `~/.config/waybar/config`:

```json
"custom/usemeter": {
  "format": "🤖 ${}",
  "interval": 60,
  "exec": "curl -sS -H 'Authorization: Bearer um_pat_YOUR_TOKEN_HERE' https://usemeter.example.com/api/v1/summary | jq -r '\"$\" + (.totals.totalBalanceUsd // 0 | tostring)'",
  "tooltip-format": "{tooltip}",
  "tooltip": "useMeter AI Usage Tracker"
}
```

### 3.2. Tmux Status Bar

Add to `~/.tmux.conf`:

```tmux
# Refresh AI balance every 5 minutes in status-right
set -g status-right '#(curl -sS -H "Authorization: Bearer um_pat_YOUR_TOKEN_HERE" https://usemeter.example.com/api/v1/summary | jq -r "\"AI: $\" + (.totals.totalBalanceUsd|tostring)") | %H:%M'
```

### 3.3. Terminal CLI Script (`usemeter-cli`)

Create `~/.local/bin/ai-balance` (make executable with `chmod +x`):

```bash
#!/usr/bin/env bash
set -euo pipefail

TOKEN="${USEMETER_TOKEN:-}"
URL="${USEMETER_URL:-https://usemeter.example.com}"

if [[ -z "$TOKEN" ]]; then
  echo "Error: USEMETER_TOKEN environment variable is not set." >&2
  exit 1
fi

DATA=$(curl -fsS -H "Authorization: Bearer ${TOKEN}" "${URL}/api/v1/summary")

TOTAL_BAL=$(echo "$DATA" | jq -r '.totals.totalBalanceUsd')
TOTAL_SPENT=$(echo "$DATA" | jq -r '.totals.totalSpentUsd')
ACCOUNTS=$(echo "$DATA" | jq -r '.totals.activeAccounts')

printf "AI Providers Summary (%s accounts):\n" "$ACCOUNTS"
printf "  Prepaid Balance : $%s\n" "$TOTAL_BAL"
printf "  Key Spending    : $%s\n" "$TOTAL_SPENT"
echo ""
echo "Accounts Breakdown:"
echo "$DATA" | jq -r '.accounts[] | "  - \(.accountLabel) (\(.provider)): \(.health) | Balance: $\(.balanceUsd // "N/A") | Spent: $\(.spentUsd // "N/A")"'
```

---

## 4. Error Responses

All error responses return standard JSON envelopes with descriptive HTTP status codes:

| HTTP Status | Error Code | Description |
| --- | --- | --- |
| `401 Unauthorized` | `UNAUTHENTICATED` | Missing, malformed, invalid, or expired Bearer token. |
| `403 Forbidden` | `FORBIDDEN` | Target resource does not belong to the authenticated user. |
| `404 Not Found` | `NOT_FOUND` | Credential or token ID does not exist. |
| `429 Too Many Requests` | `RATE_LIMITED` | Request rate limit exceeded. Check the `Retry-After` header. |
| `429 Too Many Requests` | `TOKEN_LIMIT_REACHED` | Attempted to create more than 25 active tokens. |
| `500 Internal Error` | `INTERNAL_ERROR` | Server-side execution failure. |
