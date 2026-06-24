# Project-Scoped Rules

- **`DashMap::entry` lock contention**: Never use `DashMap::entry()` on a hot path. 
  - **Why**: `DashMap::entry` takes an exclusive write lock immediately on the shard, effectively serializing concurrent traffic on cache hits.
  - **How to apply**: Use `.get()` first. On miss, fallback to `.entry()` or `.insert()`.
