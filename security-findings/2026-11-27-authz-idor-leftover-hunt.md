# Focalboard AuthN/AuthZ/IDOR leftover hunt — 2026-11-27

- Commit: `aaf3c4e7206ab2f53860ce281b7604fe1c13c4e2`
- Run: `bc-3d8a10d6-b4f4-5016-9aac-bf9669632ccd`
- Result: **NONE** — no NEW validated MEDIUM/HIGH/CRITICAL AuthZ/IDOR/priv-esc findings with a complete cross-trust attack chain

## Do-not-report (still present; not re-validated as new)

1. Open-board editors grant SchemeAdmin via POST `/boards/{id}/members`
2. File IDOR: auth on URL `boardID`, serve via global `FileInfo.Path`
3. Editors can set `ChannelID` without channel membership via PATCH `/boards-and-blocks` / POST `/boards`
4. Team archive export dumps open-board content without ViewBoard (standalone)
5. Template upload path traversal via attacker-controlled `teamId`
6. Category `boardID` plant (SQLi precursor; already reported)

## Surfaces re-traced this run

| Surface | Handler / code | Outcome |
|---|---|---|
| `sessionRequired` vs `attachSession(false)` | `auth.go`, route regs | Optional session only on get board/blocks/files (+ read_token); mutations require session |
| Guests join/create/templates/onboard/import | `members.go`, `boards.go`, `templates.go`, `onboarding.go`, `archive.go` | Guests correctly denied create/join/templates/onboard/import |
| Sharing / read_token / public boards | `sharing.go`, `auth/auth.go` | Needs `ShareBoard` + `enablePublicSharedBoards`; empty token is admin footgun only |
| WS AUTH / SUBSCRIBE_BLOCKS / SUBSCRIBE_TEAM / CheckOrigin | `ws/server.go` | Block subscribe needs valid read_token for owning board; team subscribe needs ViewTeam; plugin mode has no unauth block subscribe |
| Users GetUsersList / GetTeamUsersByID / CanSeeUser | `users.go`, `teams.go`, `app/user.go` | POST `/users` filters CanSeeUser; POST team users-by-ID skips it (see rejected) |
| SearchBoardsForUser team scoping | `search.go`, mattermostauthlayer | Open boards by design; membership/channel scoped |
| Duplicate / CopyAndUpdateCardFiles | `blocks.go`, `files.go` | Duplicate needs ViewBoard (or open-template ViewTeam); `sourceBoardID` copies then PatchBlocks on regenerated IDs fails — no content exfil chain |
| MoveContentBlock | `content_blocks.go`, `app/content_blocks.go` | ManageBoardCards on source; ParentID match + contentOrder membership block cross-board |
| Cards BoardID vs URL | `cards.go` | Create rejects mismatch; get/patch auth on `card.BoardID` |
| handlePatchBlocks ignores URL boardID | `blocks.go` | Auth still per `block.BoardID` with ManageBoardCards |
| Categories update/delete/hide / plant | `categories.go`, `app/category*.go` | Ownership enforced in app; plant without ViewBoard is sidebar-only (SQLi covered by #6) |
| Templates / onboarding | `templates.go`, `onboarding.go` | Open templates ViewTeam-only intentional; guests denied |
| Compliance / statistics / admin set-password | `compliance.go`, `statistics.go`, `admin.go` | manage_system+license / get_analytics / unix socket |
| mmpermissions synthetic editor | `mattermostauthlayer.go` | ChannelMembers → editor when ChannelID set (known #3); open-template viewer; guests excluded |
| CreateSubscription without ViewBoard | `subscriptions.go`, notifysubscriptions | Self-only create; delivery re-checks ViewBoard |
| ChangePassword path userID | `auth.go` | Needs oldPassword; no session.UserID==path check but password knowledge required |
| Mass assignment BoardPatch / BlockPatch | `boards.go`, `boards_and_blocks.go`, `model/block.go` | Type/MinimumRole gated ManageBoardType on PATCH board; ChannelID on boards-and-blocks is known #3; BlockPatch has ParentID not BoardID |
| Sessions / cookies / CSRF | `api.go`, `request_parser.go` | `/api/v2` requires `X-Requested-With: XMLHttpRequest` |
| Linux LocalOnly false + attachSession false | config + handlers | Unguessable 128-bit board IDs; read_token still required for anon |
| Import archive boardMembers / ChannelID | `import.go` | Members/ChannelID only affect attacker-owned newly imported boards |
| Mentions auto-add | `notifymentions/mentions_backend.go` | Open boards only; intentional |
| Last-admin TOCTOU | `app/boards.go` | Griefing race; no durable priv-esc |
| Join MinimumRole=admin floor | `members.go` | Intentional |
| Empty share token WS | `auth/auth.go` | Needs enablePublicSharedBoards + empty Token set by ShareBoard holder |

## Most interesting rejected candidates (why incomplete / below bar)

### 1. Guest bypass of CanSeeUser on POST `/teams/{teamID}/users`
- **Evidence:** `handleGetTeamUsersByID` (`server/api/teams.go`) checks ViewTeam only; calls `GetUsersList` with no `CanSeeUser` / no `SanitizeProfile`. Parallel POST `/users` and GET team users enforce guest restrictions.
- **Attack:** Guest with ViewTeam POSTs arbitrary user IDs → username / nickname / names (if ShowFullName) / is_bot / is_guest / Permissions (`manage_team` / `manage_system` flags). Email is `json:"-"` and `baseUserQuery` does not select `roles`.
- **Why not MEDIUM+:** Info disclosure without email/secrets; no privilege escalation or private board/content access. Prior hunts correctly discarded as below the complete-chain bar for AuthZ impact.

### 2. CopyAndUpdateCardFiles(`sourceBoardID`) without source ViewBoard
- **Evidence:** `handlePostBlocks` accepts `sourceBoardID` after `GenerateBlockIDs`; `CopyCardFiles` reads source board files with no permission check.
- **Why fails:** New block IDs do not exist yet when `PatchBlocks` runs → request errors; in-memory blocks keep old `fileId`; new dest filenames are unguessable `NewID`s. Side-effect file copy without a readable handle is not a complete exfil chain (overlaps known file IDOR class only if caller already has filenames).

### 3. Signup token GET + regenerate without admin role (standalone)
- **Evidence:** `handleGetTeam` returns `signupToken` JSON; `handlePostTeamRegenerateSignupToken` is session-only (no ManageTeam).
- **Why fails:** Personal-server invite UX (any member can invite); regenerate returns `{}` (token only via subsequent GET). Not a cross-trust escalation into another tenant.

### 4. POST `/boards-and-blocks` only ViewTeam (not CreatePublicChannel)
- **Evidence:** Unlike POST `/boards`, BAB create skips create-public/private channel permission.
- **Why fails:** Product tests expect any team member to create boards this way; guests still denied. Capability is intentional board creation, not channel privilege escalation.

### 5. Category boardID plant without ViewBoard (non-SQLi)
- **Evidence:** `handleUpdateCategoryBoard` → `AddUpdateUserCategoryBoard` with no ViewBoard check.
- **Why fails:** Sidebar mapping only for the caller's own categories; does not grant ViewBoard/content. Content impact requires the already-reported reorder SQLi (#6).

### 6. CreateSubscription without ViewBoard
- Self-only subscriberID; `notifysubscriptions` delivery re-checks ViewBoard before notify. No content leak.

### 7. handlePatchBlocks ignores URL boardID
- Auth loops `GetBlockByID` + `HasPermissionToBoard(..., ManageBoardCards)` per block. No cross-board write without already having card manage on each board.

### 8. Empty share token / CheckOrigin:true / LocalOnly:false
- Empty token requires admin enabling sharing with blank token + `enablePublicSharedBoards`. WS AUTH uses message token (not cookie). Optional-session endpoints still need valid read_token or membership; board IDs are unguessable.

## Verdict

Leftover AuthN/AuthZ/IDOR surfaces after excluding the six known findings yield **no new complete MEDIUM+ cross-trust attack chains** at commit `aaf3c4e7206ab2f53860ce281b7604fe1c13c4e2`.
