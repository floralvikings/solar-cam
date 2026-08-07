# PTZ controls overlaid on the live image (Lovelace card)

Home Assistant's built-in **Picture Elements** card draws clickable icons on top
of a camera feed — so you get a D-pad directly over the live view, no custom
frontend code and no HACS frontend plugin.

## 1. Find your entity IDs
**Settings → Devices & Services → Devices → RBX-S73 …** and note the IDs
(or Developer Tools → States, filter `rbx`). They look like:

```
camera.rbx_s73_192_168_88_113
button.rbx_s73_192_168_88_113_pan_left
button.rbx_s73_192_168_88_113_pan_right
button.rbx_s73_192_168_88_113_pan_up
button.rbx_s73_192_168_88_113_pan_down
button.rbx_s73_192_168_88_113_pan_stop
```

## 2. Add the card
Dashboard → **Edit** → **+ Add Card** → **Manual**, then paste this and replace
the entity IDs with yours:

```yaml
type: picture-elements
camera_image: camera.rbx_s73_192_168_88_113
camera_view: live
elements:
  # ---- up ----
  - type: icon
    icon: mdi:chevron-up
    tap_action:
      action: perform-action
      perform_action: button.press
      target:
        entity_id: button.rbx_s73_192_168_88_113_pan_up
    style: &btn
      top: 70%
      left: 88%
      color: white
      background: rgba(0,0,0,0.45)
      border-radius: 50%
      padding: 6px
      transform: translate(-50%, -50%)
  # ---- down ----
  - type: icon
    icon: mdi:chevron-down
    tap_action:
      action: perform-action
      perform_action: button.press
      target:
        entity_id: button.rbx_s73_192_168_88_113_pan_down
    style:
      <<: *btn
      top: 92%
  # ---- left ----
  - type: icon
    icon: mdi:chevron-left
    tap_action:
      action: perform-action
      perform_action: button.press
      target:
        entity_id: button.rbx_s73_192_168_88_113_pan_left
    style:
      <<: *btn
      top: 81%
      left: 81%
  # ---- right ----
  - type: icon
    icon: mdi:chevron-right
    tap_action:
      action: perform-action
      perform_action: button.press
      target:
        entity_id: button.rbx_s73_192_168_88_113_pan_right
    style:
      <<: *btn
      top: 81%
      left: 95%
  # ---- stop (centre of the D-pad) ----
  - type: icon
    icon: mdi:stop-circle-outline
    tap_action:
      action: perform-action
      perform_action: button.press
      target:
        entity_id: button.rbx_s73_192_168_88_113_pan_stop
    style:
      <<: *btn
      top: 81%
```

The D-pad sits in the bottom-right corner. Move the whole cluster by shifting the
`top`/`left` percentages (they're relative to the image, so it scales with the card).

Notes:
- `camera_view: live` streams; use `auto` if you'd rather it show a still until
  clicked (gentler on a battery/solar camera).
- YAML anchors (`&btn` / `<<: *btn`) just avoid repeating the style block. If your
  editor dislikes them, paste the style into each element instead.
- On older Home Assistant versions replace
  `action: perform-action` / `perform_action:` with `action: call-service` / `service:`.

## 3. Tune how far each press moves
**Settings → Devices & Services → RBX-S73 → Configure →
“Pan/tilt movement per button press (seconds)”** (default **0.25 s**, range
0.05–5.0). No restart needed — the next press uses the new value.

The command starts continuous motion and runs until STOP, so this duration is
exactly what sets the travel distance per press.

## Behaviour worth knowing
- The **first press after idle takes a few seconds** — the camera has to wake,
  bring video up and complete the knock/confirm handshake. Later presses are
  quick because the session is held ~12 s.
- The camera serves **one session at a time**, so PTZ shares the same session as
  the live view — no conflict, but a press while the stream is starting may wait.
