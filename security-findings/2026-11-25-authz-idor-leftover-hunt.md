# AuthN/AuthZ/IDOR leftover hunt — NONE

**Commit:** `a84bbb65e32edf972856b329417096ac413518e9`  
**Scope:** websocket subscribe/broadcast, sharing `read_token`, guests, templates, duplicate, cards/content_blocks `parentID`, users/teams, admin, onboarding, statistics, compliance, mmpermissions synthetic members, notifications, search, import/export, `CopyCardFiles`/`MoveFile`, sessions, mass assignment, public-share CSRF, privilege-escalation races  
**Result:** **NONE** — no NEW MEDIUM+ AuthN/AuthZ/IDOR/priv-esc findings with a complete cross-trust attack chain beyond the already-reported/rejected set.

## Already reported (not re-reported)

1. Open-board editor → SchemeAdmin via `POST /boards/{id}/members` (`server/api/members.go`)
2. File IDOR: auth on URL `boardID`, serve via global `FileInfo.Path` (`server/api/files.go`, `server/app/files.go`)
3. `ChannelID` without channel membership via `PATCH /boards-and-blocks` and `POST /boards`
4. Team archive export dumps open-board content without `ViewBoard` (`server/api/archive.go`)

(Plus prior non-authz findings: category/`category_boards` SQLi, Prometheus, markdown XSS, template `teamId` path traversal.)

## Strongest near-misses (why they fail)

1. **`CopyAndUpdateCardFiles` / `sourceBoardID` without `ViewBoard`** (`server/api/blocks.go:297-302`, `server/app/files.go:185-300`)  
   Copies via global `GetFilePath`/`FileInfo`, but `GenerateBlockIDs` runs first so `PatchBlocks` fails on non-existent IDs; request errors before the client learns new filenames. Same FileInfo global-lookup class as reported file IDOR.

2. **`ChannelID` + `MoveFile`/`GetFileReader` fallback** (`server/api/files.go:156-168`, `server/app/files.go:132-184`)  
   Malicious `ChannelID` (via known #3 / standalone always-true `HasPermissionToChannel`) is joined as `channelID/boardID/filename`. URL `boardID` remains the attacker board, so the path cannot be remapped onto a victim board’s files without the known FileInfo IDOR. Incomplete new chain.

3. **`MoveContentBlock` ParentID cross-board** (`server/api/content_blocks.go:83-86`, `server/app/content_blocks.go:10-73`)  
   Authz is on source `block.BoardID` only; ParentIDs can be set freely on insert/patch. Move still requires both block IDs to already appear in the parent card’s `contentOrder`, so victim cards are not mutated.

4. **WS `SUBSCRIBE_BLOCKS` + `read_token`** (`server/ws/server.go:158-175`, `247-282`)  
   Token must validate for the board that owns every listed block; broadcasts to block listeners are the intended public-share path. `CheckOrigin: true` alone does not grant data without a valid token/session.

5. **Cookie session + public-share CSRF** (`server/services/auth/request_parser.go:45-48`, `server/api/api.go:134-148`)  
   State-changing `/api/v2` routes require `X-Requested-With: XMLHttpRequest`, blocking simple cross-origin cookie CSRF.

6. **Synthetic → explicit member via `AddMemberToBoard`** (`server/app/boards.go:527-529`)  
   Synthetic memberships are overwritten only when `AddMember` is allowed; private boards still require `ManageBoardRoles`. Open-board editor → admin is already reported (#1).

7. **`CreateSubscription` without `ViewBoard`** (`server/api/subscriptions.go:78-96`)  
   Delivery re-checks `ViewBoard` (`notifysubscriptions`).

8. **Signup token GET / regenerate** (`server/api/teams.go:66-179`)  
   Invite UX on Personal Server; regenerate returns `{}` (token re-read via GET team).

9. **`handlePatchBlocks` ignores URL `boardID` / empty `teamID`** (`server/api/blocks.go:625-663`)  
   Auth still evaluated per `block.BoardID`.

10. **`handleUpdateCategoryBoard` no `ViewBoard`** (`server/api/categories.go:379-385`)  
    Sidebar mapping only; SQLi impact of planted board IDs already reported separately (injection hunt).

## Re-traced (gates held)

- Guests denied join/create/templates/onboard/archive-import  
- Open-template read/duplicate with `ViewTeam` only (intentional)  
- Sharing needs `ShareBoard` + `enablePublicSharedBoards`  
- Compliance/statistics require `manage_system` / `get_analytics` + license  
- Admin set-password requires unix socket (`adminRequired`)  
- mmpermissions team-admin elevation when already a member (intentional)  
- Mention auto-add on open boards (intentional)  
- Join `MinimumRole=admin` floor (intentional)  
- Import archive members/`ChannelID` only on newly imported attacker-owned boards  
