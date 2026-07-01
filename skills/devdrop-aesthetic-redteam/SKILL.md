---
name: devdrop-aesthetic-redteam
description: Attack generic AI-dashboard visuals in DevDrop UI: SaaS sameness, fake glass, weak hierarchy, meaningless cards, noisy colors, and lazy components.
---

# DevDrop Aesthetic Red-Team

## When To Use

- Use for every visual UI change, route shell, design-system component, dashboard layout, workflow view, icon treatment, color palette, motion idea, or empty state.
- Use when the surface risks looking like a generic AI dashboard or default component-kit demo.
- Use alongside UX red-team when visual choices affect trust or safety comprehension.

## When Not To Use

- Do not use for backend-only code unless user-facing copy or visual artifacts changed.
- Do not use to prefer novelty over clarity.
- Do not use to add decorative visuals that do not explain workspace state.

## Required Inputs

- Screen or component name.
- Intended user job and evidence the screen must show.
- Screenshot, route, mock, or code reference.
- Current color, typography, spacing, icon, card, and motion choices.
- Any relevant fixture state.

## Required Outputs

- Aesthetic findings ordered by severity.
- Specific slop patterns found or ruled out.
- Visual direction corrections.
- Evidence-first composition notes.
- Pass/fail against DevDrop aesthetic bans.

## Checklist

- Reject default shadcn sameness, fake glassmorphism, random sparkles, vague pills, meaningless metric cards, and purple/blue AI gradients.
- Reject generic SaaS dashboards, over-rounded everything, noisy severity colors, and decorative visuals that do not explain state.
- Prefer calm, spatial, tactile, trust-centered, inspectable workspace state.
- Make machine topology, object state, queues, tombstones, conflicts, and hydration visibly physical or map-like.
- Keep hierarchy precise: primary evidence first, next action second, decoration last or absent.
- Use restrained safety color only where it carries meaning.

## Examples

- "Dashboard cards" -> challenge whether each card explains workspace readiness or just fills a grid.
- "Machine Map" -> prefer spatial topology and path mapping over generic list rows.
- "Conflict Center" -> prefer inspectable object comparison over bright severity badges.

## Failure Modes

- UI looks like a template with DevDrop nouns pasted in.
- Visual interest comes from gradients instead of workspace evidence.
- Cards multiply without changing user understanding.
- Safety states rely on color alone.
- Components are polished but do not answer whether the user can safely work.
