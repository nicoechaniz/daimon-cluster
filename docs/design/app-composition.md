# A shared composition language for Matrix apps

Matrix apps should feel related without becoming copies of the same screen.
This direction comes from Nicolás's 2026-10-26 request to carry the recent
PsicopoMPo and Interaction work into Apps and application templates.

## References and actual scope

The current [PsicopoMPo application](https://psicopompo.altermundi.net/) has an
authored material background, restrained chrome, clear typography and a prominent
contextual action. Its public entry was inspected on 2026-10-26. Its authenticated
interior was not inspected; the older public landing/branding repositories are
not evidence of the current operational interface.

[Interaction](https://github.com/AlterMundi/telecodex/tree/master/dashboard/web)
already separates the conversation, stable composer and secondary inspector.
[PR265](https://github.com/AlterMundi/telecodex/pull/265) explicitly records that
reference-driven visual refinement was still pending. Its authored appearance
does not establish a universal exception to Homemaker inheritance.

Transfer composition and interaction lessons. Do not copy PsicopoMPo's mascot,
material artwork, brand palette or Beacon Account authentication into another app.

## Patterns to reuse

- **Orient before asking.** Identify the app and current subject in a compact
  header. Put the useful content immediately below it rather than behind a large
  decorative introduction.
- **Give the main activity the space.** Conversation and monitoring surfaces
  use a compact header, an expanding content region and stable contextual
  controls. A document or catalogue can scroll naturally. Do not constrain an
  otherwise empty screen to a small scrolling box.
- **Group by meaning, not by rectangles.** Use typography, proximity and quiet
  separators before enclosing every item in another card. Keep complete titles,
  descriptions, dependencies, source attribution and errors readable.
- **Keep primary actions stable.** Loading, playback or status changes should
  not move Send or the recording control. Secondary actions belong beside the
  relevant object or in a clearly labelled inspector, not in a competing console.
- **Make detail reachable.** Progressive disclosure reduces simultaneous controls;
  it must not remove the inventory, essential access information or recovery path.
  Show counts and filters where they explain what is visible.
- **Use appearance roles consistently.** Background, surface, text, accent,
  fonts, radius and spacing come from the existing `--dm-*` consumer. A soft
  background treatment or fine separator derives from those same roles. There
  is no new theme store, forced historical palette or second Homemaker instance.
- **Distinguish absence from failure.** Empty, loading, stale, partially available,
  waiting and failed are different states. Decoration never supplies evidence
  of work or successful delivery.

These are composition patterns for app authors, not a new frontend framework or
a copied Homemaker template catalog. Reuse each application's actual components,
navigation, authentication and state ownership.

## First consuming surface: Apps

The launcher uses a quiet masthead and search, then a readable tool directory.
Narrow screens use full-width entries; wider screens use two columns. Descriptions
remain complete, and the favorite control keeps its own touch target. Selection
of the receiving pair, alert navigation, current catalogue, initial rendering and
the maintained appearance consumer keep their existing behavior.

No JavaScript, catalogue, private permission or publication contract changes are
required for this composition. See [launcher ownership](miniapps-launcher.md)
and [shared appearance](shared-home-styles.md).

## Application templates and other receivers

Homemaker remains the maintained Ani/Oliva application. This work neither edits
its templates nor installs a second creator. Nicolás explicitly required asking
before modifying Oli's or Eko's work; proposed contributions and their receiving
deployment must respect that restriction. A change to Apps is not adoption by
their own apps, bots or bodies.

Sessions, Nexus, Collective Research and other applications can use these patterns
through focused changes to their own layouts. Qualify each actual journey rather
than claiming that a shared stylesheet automatically redesigns every app.

For each consumer, check phone and desktop layouts, narrow reflow, keyboard focus,
full-length content, light/dark appearances, loading/failure and the main action.
Keep browser fixtures, production delivery and human aesthetic acceptance distinct.
