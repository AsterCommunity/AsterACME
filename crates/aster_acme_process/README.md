# aster_acme_process

Bounded child-process lifecycle management for AsterACME reload commands and external DNS providers.

Commands use an executable path and exact argv values; no shell parsing is performed. The runner bounds stdin, stdout, stderr, deadlines, cancellation, output retention, and process-tree cleanup. Unix process groups and Windows Job Objects keep owned descendants within the lifecycle boundary.

The adapter drains output after retention limits, reports truncation, clears inherited environment variables when requested, and preserves uncertain side effects after a timeout or lost response. Business retry and provider ownership decisions remain with the caller.

```sh
cargo test -p aster_acme_process --locked
```

License: MIT OR Apache-2.0.
