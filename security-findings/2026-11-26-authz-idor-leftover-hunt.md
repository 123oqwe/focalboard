# AuthN/AuthZ/IDOR leftover hunt — NONE

**Commit:** `aaf3c4e7206ab2f53860ce281b7604fe1c13c4e2`  
**Scope:** All `server/api/*.go` handlers for skipped `sessionRequired` / `HasPermissionToBoard|Team`; sharing enable/token/WS; guest + `MinimumRole` + `SchemeAdmin` mass-assign; block `ParentID`/`BoardID`; category update/delete/hide ownership TODOs; teams/sessions; public templates/onboarding/statistics/compliance/subscriptions; permission races; Mattermost vs local permissions; WS SUBSCRIBE; `getFileInfo` metadata; board type changes; channel-linked membership  
**Result:** **NONE** — no NEW MEDIUM/HIGH/CRITICAL AuthN/AuthZ/IDOR/priv-esc findings with a complete cross-trust attacker chain beyond the already-reported and already-rejected sets.

## Already reported (not re-reported)

1. Open-board editor → `SchemeAdmin` via `POST /boards/{id}/members` (`server/api/members.go`)
2. File IDOR: auth on URL `boardID`, serve/metadata via global `FileInfo.Path` (`server/api/files.go`, `server/app/files.go`) — includes `/info`
3. `ChannelID` without channel membership via `PATCH /boards-and-blocks` and `POST /boards`
4. Team archive export dumps open-board content without `ViewBoard` (`server/api/archive.go`)
5. Template upload path traversal via `teamId` (`server/app/files.go`)
6. Category / `category_boards` SQLi (two)
7. XSS `javascript:` markdown
8. Prometheus unauthenticated

## Rejected near-misses (this run)

1. **`getFileInfo` global metadata by filename** (`server/api/files.go:247-318`, `server/app/files.go:55-71`)  
   Same auth-on-URL-board / global-FileInfo class as reported file IDOR #2; not a separate complete chain.

2. **Category ownership TODOs** (`server/api/categories.go:384`, hide/unhide, `AddUpdateUserCategoryBoard`)  
   Update/Delete verify stored `UserID` in app layer. Hide/unhide/`AddUpdate` filter by session `userID` on write. Cross-user plant into another `category_id` is sidebar pollution / SQLi plant already covered by reported injection finding; category IDs are not team-broadcast.

3. **`BlockPatch.ParentID` / cross-board reparent** (`server/model/block.go:87-90`, `server/api/blocks.go:541-575`)  
   `BoardID` is not patchable; authz is on URL/`block.BoardID`. Cross-board `ParentID` is integrity noise only. `MoveContentBlock` still requires shared parent + `contentOrder` membership.

4. **WS `SUBSCRIBE_BLOCKS` / team broadcast** (`server/ws/server.go:148-282`, `479-565`)  
   Read token must match the board owning every block; team broadcasts filtered by `GetMembersForBoard`. Empty token needs `enablePublicSharedBoards` + admin empty-token footgun (prior reject).

5. **Sharing get/post** (`server/api/sharing.go`)  
   Requires `ShareBoard` + `EnablePublicSharedBoards`. Token stamped to URL board ID.

6. **Guest / `MinimumRole` / `PUT` member**  
   Guests blocked from join/create/templates/onboard/import. `PUT .../members/{userID}` requires `ManageBoardRoles`. Join `MinimumRole=admin` floor intentional. Open-board editor `POST` members → admin is reported #1.

7. **Board type / `MinimumRole` patch** (`server/api/boards.go:350-354`, `boards_and_blocks.go:235-239`)  
   Gated by `ManageBoardType` (admin). Editors cannot flip private↔open.

8. **Channel-linked synthetic editors** (`mattermostauthlayer.GetMemberForBoard`)  
   Only after `ChannelID` is set; setting without membership is reported #3. Open-board GET leaking `channelId` metadata alone does not grant channel membership or ViewBoard.

9. **Sessions / signup / change-password**  
   Logout uses own session ID. `ChangePassword` needs `oldPassword`. Signup token GET/regenerate is Personal Server invite UX (prior reject). Cookie/Bearer CSRF blocked by `X-Requested-With` on `/api/v2`.

10. **Subscriptions / mentions / onboarding / compliance / statistics**  
    CreateSubscription self-only; delivery re-checks ViewBoard. Mention auto-add on open boards intentional. Onboarding needs ViewTeam + non-guest. Compliance `manage_system`+license; statistics `get_analytics`+plugin-only.

11. **`POST /boards-and-blocks` ViewTeam-only create** / **`CopyAndUpdateCardFiles(sourceBoardID)`** / **import boardMembers** / **`handleGetTeamUsersByID` skip CanSeeUser** / **last-admin TOCTOU** / **attachSession LocalOnly** — prior rejects; re-confirmed gates or incomplete chains.

## Re-traced gates that held

- `attachSession(required=false)` surfaces still require session or valid `read_token` before board data
- Cards API authz on `card.BoardID`; content-blocks move authz on source board
- Duplicate clears `ChannelID`; open-template ViewTeam-only read/duplicate intentional
- Admin set-password unix-socket only
- mmpermissions team-admin elevation only when already a board member (intentional)
- localpermissions standalone `HasPermissionToChannel=true` does not add a new ChannelID write path beyond known #3
