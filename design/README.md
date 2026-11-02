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
| preview | ready, moving, done, thanks | source, logins, extensions, bookmarks, history, movingLine, target | move, done, coffee, follow, not-now |
| home | home, undone | lastSync, undoPoint | undo, ok |
| blocked | blocked | browser | retry |

`thanks` shows once after the first move. Tapping outside = not-now.

Loader modes: `dance`, `wait`, `show`, `still`.

## Frames

Drop `name.outline.svg` + `name.mask.svg` (or transparent png) in `loader/frames/`, same canvas, feet on the same line, list them in `manifest.js`.
