# CRITICAL: Second-order SQLi in category board reorder

**Commit:** `a84bbb65e32edf972856b329417096ac413518e9`  
**Severity:** Critical  
**Component:** `server/api/categories.go`, `server/services/store/sqlstore/category_boards.go`

## Summary

Authenticated users can plant an arbitrary `boardID` (including SQL metacharacters) into `category_boards` via:

`POST /api/v2/teams/{teamID}/categories/{categoryID}/boards/{boardID}`

That handler does not verify board existence or board permissions. A later:

`PUT /api/v2/teams/{teamID}/categories/{categoryID}/boards/reorder`

concatenates those IDs into a squirrel `CASE board_id WHEN '<id>'` expression as raw SQL, enabling second-order SQL injection.

Prior analysis incorrectly treated this sink as safe because *board primary keys* are server-generated; `category_boards.board_id` is not.

## Attacker

Any authenticated user with team view (standalone Personal Server: any registered user).

## Controls

- Full URL path `boardID` string (URL-encoded quotes, semicolons, spaces).
- Reorder body must list exactly the IDs already stored for that category (including the planted payload).

## Impact

Arbitrary SQL as the Focalboard database user. On default `sqlite3`, stacked statements can copy `users.password` into the attacker-readable category `name`. On MySQL, short payloads within `VARCHAR(36)` still allow in-statement injection (e.g. time-based).

## Evidence

| Step | Location |
|------|----------|
| No board authz on plant | `server/api/categories.go:379-385` |
| Bound INSERT of raw boardID | `server/services/store/sqlstore/category_boards.go:70-94` |
| Set-equality only on reorder | `server/app/category_boards.go:212-262` |
| Unsafe When() concat | `server/services/store/sqlstore/category_boards.go:142-144` |
| Default SQLite | `config.json:3-4` |

## Remediation

1. Require the board to exist and `PermissionViewBoard` before `AddUpdateCategoryBoard`.
2. Use bound placeholders for CASE arms in `reorderCategoryBoards` (never string-concatenate IDs).
3. Restrict path `boardID` to the server ID alphabet.

## Notes

Distinct from the already-reported category *sidebar* reorder SQLi (client-chosen category `id` JSON). Same bug class, different plant path and column.
