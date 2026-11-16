# Personal OpenAI keys

When enabled by the dispatcher operator, **Account → AI assistant** lets you
save, replace, test or delete your own OpenAI API key. Sign in again if your
browser session is more than ten minutes old before changing these settings.
The key is never included in an experiment or sent to executors. The dispatcher
decrypts it only to contact OpenAI; this requires trusting the dispatcher operator.

The assistant shows whether requests use your personal key or the operator's
service. Your key takes precedence whenever it is saved. OpenAI bills usage to
the project owning that key, separately from Debuglet experiment credits.
An invalid or exhausted personal key produces an error and never retries using
the operator's key. Deleting your key restores the operator service if available;
otherwise the assistant is disabled for your account. Deletion affects new
requests; a request already running may finish with the key it started with.

**Test access** checks whether OpenAI permits access to the configured model. It
does not generate tokens or verify remaining credit, generation quota or that a
particular experiment will succeed. Saving a key does not make a provider request.
The existing experiment review, validation, compilation and launch flow is unchanged.

## Enable on a dispatcher

Create a dedicated encryption key once, outside the repository and database:

```sh
umask 077
openssl rand -base64 32 > /etc/debuglet/assistant-encryption.key
```

The dispatcher service must be able to read that regular file. Restrict its
permissions to `0600` or `0640`; never make it readable by other users.
Apply the database migrations and configure:

```toml
[studio.assistant]
enabled = true
personal_key_file = "/etc/debuglet/assistant-encryption.key"
personal_model = "your-openai-model"
reasoning_effort = "high"
```

Choose an OpenAI model supported by your deployment. Personal keys always use
`https://api.openai.com/v1/responses`; they cannot be redirected to the operator's
custom endpoint. `personal_model` is separate from the operator's `model`.
The existing `endpoint`, `model` and `api_key_file` settings optionally configure
an operator service. A personal-key-only deployment needs none of those settings
and no `DEBUGLET_ASSISTANT_API_KEY`. Normal assistant concurrency and rate limits
apply to both sources.

The database stores one AES-256-GCM encrypted credential per account, bound to
that account's identity. Back up the encryption key separately from the database
and retain it across restarts and upgrades. Replacing or losing the encryption
key makes existing credentials unreadable; it does not silently activate operator
billing. Users can delete or replace an unreadable credential after signing in.
Deleting a key removes the active database record; old encrypted backups remain
subject to the operator's backup-retention policy. Revoking the key at OpenAI
also invalidates copies retained in backups.
