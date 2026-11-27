# Focalboard logic / crypto / XSS / desktop / infra hunt — 2026-11-27

- Commit: `aaf3c4e7206ab2f53860ce281b7604fe1c13c4e2`
- Run: `bc-31b515fa-5008-5216-89cd-35e3a57d07d2`
- Result: **NONE** — no NEW validated MEDIUM/HIGH/CRITICAL findings with a complete realistic attack chain

## Already reported (not re-reported)

1. CRITICAL category-reorder SQLi (`category.go` CASE WHEN)
2. HIGH open-board editor grants SchemeAdmin via POST members
3. HIGH file IDOR via global `FileInfo.Path`
4. MEDIUM default Prometheus `:9092` unauthenticated
5. HIGH ChannelID via PATCH boards-and-blocks / POST boards
6. HIGH stored XSS via `javascript:` markdown links
7. HIGH template `SaveFile` teamId path traversal
8. HIGH team archive export without ViewBoard
9. CRITICAL category_boards reorder SQLi via URL boardID plant

## Surfaces re-traced

| Area | Evidence | Outcome |
|---|---|---|
| Last-admin race | `app/boards.go` `isLastAdmin` / `DeleteBoardMember` / `UpdateBoardMember` | TOCTOU griefing only |
| Join / MinimumRole / allow_admin | `api/members.go` | Product semantics; ManageTeam for private |
| Sharing / read_token | `api/sharing.go`, `auth/auth.go` | Feature-flagged; HTTP empty token blocked |
| WS | `ws/server.go` CheckOrigin, AUTH, SUBSCRIBE_BLOCKS, BroadcastBlockChange ParentID | Empty-token footgun; ParentID notify redundant w/ DuplicateBoard |
| Search / guests / templates | `api/search.go`, `templates.go` | Open-board title search by design |
| Compliance / retention / cloud | `api/compliance.go`, `data_retention.go`, `cloud.go` | Admin+license; NewID IDs; limits disabled |
| Tokens / cookies / CSRF | `auth.go`, `request_parser.go`, `api.go` | CSRF X-Requested-With; SecureCookie unused |
| Desktop Linux | `linux/main.go` LocalOnly false, random port bind `:` | Unguessable board IDs for unauth SingleUser GETs |
| Docker / GHA / config | `docker/*`, `.github/workflows`, `config.json` | Prometheus already reported; demo compose rejects |
| XSS leftovers | `utils.ts`, blocksEditor, url property, favicon | Known XSS or flag-off / noreferrer |

## Rejected candidates (re-eval)

- **handleGetTeamUsersByID skip CanSeeUser** (`teams.go:340-354`): email `json:"-"`; CanSeeUser only restricts guests (`app/user.go:50-62`); guest still needs unguessable non-shared user IDs; username/`manage_system` recon incomplete for MEDIUM
- POST `/boards-and-blocks` ViewTeam-only create
- ChangePassword path `userID` (requires `oldPassword`)
- Signup token get/regenerate (invite UX; GET `/teams` already returns token)
- Login/welcome `?r=` history push
- Unauthenticated `/ping` fingerprint
- Last-admin TOCTOU griefing
- Cookie-over-Bearer; Linux LocalOnly false; admin unix set-password
- Mention auto-add; CreateSubscription self-only; WS empty share token
- newBoardsEditor XSS (flag default off); URL-property `javascript://` + noreferrer; setFavicon SVG
- bcrypt 10; SecureCookie unused; RUDDER GHA; docker.sock / POSTGRES_PASSWORD demo; non-constant-time compare; SQLite 0644; removeSecurityData noop
- Archive import teamId → template SaveFile (duplicate of known HIGH #7)
- ParentID cross-board WS notify (editor can DuplicateBoard instead)
