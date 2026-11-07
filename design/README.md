# design

UI for the app. Plain HTML/CSS/JS, no build step.

- `screens/index.html` - all screens and states
- `screens/1-welcome.html` ... `6-blocked.html` - one screen each, dev bar on top switches states
- `loader/preview.html` - the lemur loader with a progress slider

## Files

```
style/moveit.css        shared styles
style/screens.js        state switching, binds, actions, loader mount
style/icons.js          icons inlined for offline (tools/build_icons.py)
style/icons/            icon svgs, brands/ = Phosphor 2.1.1 (MIT)
style/fonts/            Figtree (OFL)
style/vendor/qrcode.js  qrcode-generator 1.4.4 (MIT)
loader/moveit-loader.js canvas loader, no deps
loader/frames/          lemur frames (outline + mask) and manifest.js
tools/                  scripts that generate frames and icons (need shapely)
```

## API

Each screen is one `.app` with `<section class="state" data-state="...">` children.

```js
MoveIt.setState("success")
MoveIt.bind({ code: "482 913", lastSync: "2 minutes ago" })   // fills [data-bind]
MoveIt.on("pair", fn)                                         // buttons use data-action
MoveIt.lemur("moving").setProgress(0.4)                       // 0..1, onDone fires when full
```

`data-go` / `data-state` on buttons are mockup-only.

| screen | states | binds | actions |
|---|---|---|---|
| welcome | welcome | | start |
| pairing | show, enter, wrong, success | code, thisDevice, otherDevice | have-code, show-code, pair, next |
| pipe | pick | pipe | pick, use-pipe |
| preview | ready, moving, done, thanks, single | source, logins, extensions, bookmarks, history, moveCount, movingLine, target, pickerProfile, pickerOwn | move, done, coffee, follow, not-now, route, route-clear, picker-close |
| home | home, undone | lastSync, undoPoint | undo, ok |
| blocked | blocked | browser | retry |

`thanks` shows once after the first move. Tapping outside = not-now.

## Preview: profiles

`preview_counts` returns one entry per browser, and under each browser one
entry per profile:

- browser: its name, its totals over the ticked profiles, and its skipped
  list (what cannot move, named with its reason; the screen shows it in the
  Cannot move card)
- profile: an id built from the browser and the profile's folder name
  (`brave:default`, `brave:profile-1`), its display name, its counts (logins,
  passwords, bookmarks, history), `is_new` when the profile was not in the
  remembered set, `remembered_excluded` when it was left out of the last
  move, and where it is headed (see routing below)

Every profile starts ticked. Unticking one dims its row and takes its
counts out of the totals and the Move button. The shell passes the unticked
profile ids to `move_start` as the excluded set; everything not excluded
moves. The unticked set is remembered per browser, and a profile that
appears later starts ticked and flagged `is_new`, so it is never absorbed
invisibly.

## Preview: routing

A profile can be sent to a different browser than its own. The destination
is chosen per profile, and one move may send different profiles to
different browsers.

`preview_counts` takes the shell's current choices, the unticked ids and
the route choices (`[{profile: id, browser: name}]`), and answers with
totals over the profiles that would actually move, each profile's
`excluded` flag and its `destination` (the browser it is headed to) and
`routed` (true when the destination is a choice, not the default), plus a
top-level `targets` list: every Chromium-family browser (Brave, Chrome,
Chromium, Edge, Opera), each with `available` and, when Move It cannot
read that browser's password on this system yet, a plain `reason`. The
combinations `move_start` refuses (a route for a left-out profile, an
unknown id) refuse here too, so the screen never promises a move the
engine will not run.

On the screen, each ticked profile row carries a quiet "Send to a
different browser" link. It opens the destination picker, a sheet listing
the profile's own browser first (choosing it clears the route), then the
other family browsers; unavailable ones show their reason and cannot be
picked. A routed profile shows a chip on its row ("Going to Chrome", with
a clear button), and a "Going somewhere else" card above the Move button
lists every route plainly ("Work to Chrome, as its own new profile").
Unticking a profile drops its route. Routes are never remembered: they
belong to the move they were chosen in. When no other browser is
available, the link is not shown at all (state `single`): routing is
quietly unavailable, never greyed out.

The shell passes the routes to `move_start(excluded, routes)` alongside
the excluded set. A route naming an unknown profile, a profile routed
twice, a route for an excluded profile, or a browser outside the family
refuses the move before anything is read or written. Routing a profile
to its own browser is the same as not routing it.

On the receiving device, a routed profile lands as a NEW profile in the
destination browser, under the profile's own name, registered in that
browser's profile list the way the browser registers profiles; it never
lands over a profile that is already there. Profiles routed to the same
browser in one move land as separate new profiles. The box a routed
profile travels in carries `profile_browser`, `profile_slot` and
`profile_name` in its manifest, plus `route_browser` when routed; each
profile travels in its own box file (`moveit-box-<browser>-<slot>.json`),
except the working profile, which keeps `moveit-box.json`.

The move report carries one line per incoming profile: where it landed
(profile name, created or merged), or that it failed and why. A profile
whose destination browser is open on the receiving device fails with the
close-it language of the blocked screen; the rest of the move still runs.
Undo covers every browser the move landed profiles in, and only that
move: a move that landed nothing leaves undo with nothing to undo.

A routed profile's first landing is stamped inside the created profile
(a `.moveit-landing` marker naming the source it was created for). Later
deliveries of the same source profile merge into that landed home, never
into a profile the marker does not name; this is what keeps the repeating
sync cycle from stacking a new copy of the profile on every move. The
source identity includes the sending device's name, so if that device is
renamed, its routed profiles land fresh once under the new name.

## Shell commands

The shell drives the engine through its app surface: one command per thing
it can ask for, each returning plain data the shell renders.

| command | what the shell gets |
|---|---|
| welcome_start | start info: paired or not, the two devices, last sync |
| pair_show_code | a pairing code to show |
| pair_enter_code | paired, wrong code (tries left), or locked out |
| use_pipe | the pipe kind, and where the sealed box lives |
| preview_counts | what would move, and what would not, named with reasons |
| move_start | progress beats, then the move report |
| home_state | last sync time, and whether the last move can be undone |
| undo_last | what the undo did |
| browser_open_check | whether the working browser is open |
| logs_recent | the newest log lines, [{ at_unix, level, message }] in time order; the screen renders them newest first |
| export_logs | the whole log as one text report, ready to save or share |

`logs_recent` and `export_logs` are new with the Logs screen. Their machinery
is in core (`core/src/logbuf.rs`): a bounded ring buffer that redacts
secret-shaped values on the way in, so a log never holds a sync key, a
password, a cookie value or a pairing code. The app-surface methods live
with the rest of the surface in `core/src/api.rs`: `logs_recent(n)` returns
`LogBuffer::recent(n)`, `export_logs()` returns `LogBuffer::export(now)`,
and the surface records each move's outcome with
`LogBuffer::record_outcome`. The shell fills the Logs screen's rows from
`logs_recent` and wires its Export button to `export_logs` plus a
save/share dialog.
## Preview: profiles

`preview_counts` returns one entry per browser, and under each browser one
entry per profile:

- browser: its name, its totals over the ticked profiles, and its skipped
  list (what cannot move, named with its reason; the screen shows it in the
  Cannot move card)
- profile: an id (like `brave:work`), its display name, its counts (logins,
  passwords, bookmarks, history), and `is_new` when the profile was not in
  the remembered set

Every profile starts ticked. Unticking one dims its row and takes its
counts out of the totals and the Move button. The shell passes the unticked
profile ids to `move_start` as the excluded set; everything not excluded
moves. The unticked set is remembered per browser, and a profile that
appears later starts ticked and flagged `is_new`, so it is never absorbed
invisibly.

Loader modes: `dance`, `wait`, `show`, `still`.

## Frames

Drop `name.outline.svg` + `name.mask.svg` (or transparent png) in `loader/frames/`, same canvas, feet on the same line, list them in `manifest.js`.
