# Class Icons

Extracted from Warspear Online client pak (Fase 6 + imgp2png tool, session 2026-09-20).

## Files

- `atlas_128.png` — 128×128 sprite atlas (all 20 classes, 5 cols × 4 rows).
- `atlas_64.png` — 64×64 mipmap variant.
- `atlas_32.png` — 32×32 mipmap variant.
- `class-names.json` — id → PT name (copy of `data/class-names.json`).

## Class list

| ID | Class (PT) |
|----|------------|
| 1  | Paladino |
| 2  | Sacerdote |
| 3  | Mago |
| 4  | Bárbaro |
| 5  | Ladino |
| 6  | Xamã |
| 7  | Dançarino da Lâmina |
| 8  | Patrulheiro |
| 9  | Druida |
| 10 | Cavaleiro da Morte |
| 11 | Necromante |
| 12 | Bruxo |
| 13 | Explorador |
| 14 | Caçador |
| 15 | Guarda |
| 16 | Encantador |
| 17 | Templário |
| 18 | Cacique |
| 19 | Invocador de Feras |
| 20 | Ceifeiro |

## Atlas layout

- `atlas_128.png` (128×128): 5×4 grid of 22×22 icons at stride 23px (starting 1,1). Contains 16 of 20 classes (row-major, top-left first): Necromante, Cavaleiro da Morte, Bruxo, Bárbaro, Ladino / Paladino, Sacerdote, Patrulheiro, Xamã, Druida / Encantador, Caçador, Mago, Dançarino da Lâmina, Explorador / Guarda + 4 filler cells.
- `atlas_64.png` (64×64): 2×2 grid at 22×22, stride 23. Contains the 4 classes missing from atlas_128 (Invocador de Feras, Ceifeiro, Cacique, Templário).
- `atlas_32.png` (32×32): only 1 icon (1×1) — role unclear, probably a small preview.

## Individual icons

`individual/` — 20 PNGs named `<id>_<class>.png` (class id matches `class-names.json`).
Mapping: `individual/class-icon-map.json`.

## Source path

`pak-out/icons/classes_240x284/class_icons_{0,1,2}.imgp`

There's also a `classes_176x208/` variant (same 3 files, same layout) — presumably for lower-DPI displays.

## Conversion command

```
./imgp2png.exe <in.imgp> <out.png>
./imgp2png.exe pak-out/icons/classes_240x284/ assets/class-icons/  # batch
```

## .imgp format

Trivial: 12-byte header (`[magic u32=0x00013233][width u32 LE][height u32 LE]`) + raw RGBA32 pixels.
