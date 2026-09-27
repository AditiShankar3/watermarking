"""
visualizers.py — plotting only. Registration diagnostics are ONE combined
figure (not four separate PNGs) and are entirely optional per-run via
`save_diagnostics=False` in pipeline.run_registration — batch/profiling runs
should always pass False so matplotlib rendering never pollutes timing runs.
"""
import os

import cv2
import matplotlib
import numpy as np

import config

# Headless-safe: only switch backend if no display is available.
try:
    import matplotlib.pyplot as plt
    if not os.environ.get("DISPLAY") and os.name != "nt":
        matplotlib.use("Agg")
except Exception:
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt


def show_registration_diagnostics(img_rgb, M_binary, M_buffer, gray_bg, LL3, dct_LL3,
                                   P_anchors_all, W_key, save_name="registration_diagnostics.png"):
    """Replaces the original four separate figures (ROI mask, frequency
    topology, anchor map, binary key) with one combined figure per
    registration, to cut down on file clutter."""
    fig = plt.figure(figsize=(18, 12))
    gs = fig.add_gridspec(3, 3, height_ratios=[1, 1, 0.4])

    ax = fig.add_subplot(gs[0, 0]); ax.imshow(img_rgb); ax.set_title("Original"); ax.axis("off")
    ax = fig.add_subplot(gs[0, 1]); ax.imshow(M_binary, cmap="gray", vmin=0, vmax=255)
    ax.set_title("YOLO mask"); ax.axis("off")
    ax = fig.add_subplot(gs[0, 2]); ax.imshow(M_buffer, cmap="gray", vmin=0, vmax=255)
    ax.set_title("Safety buffer"); ax.axis("off")

    ax = fig.add_subplot(gs[1, 0]); ax.imshow(gray_bg, cmap="gray"); ax.set_title("Background"); ax.axis("off")
    ax = fig.add_subplot(gs[1, 1]); ax.imshow(LL3, cmap="gray"); ax.set_title("LL3 - DWTx3"); ax.axis("off")
    ax = fig.add_subplot(gs[1, 2])
    ax.imshow(img_rgb)
    ya = [(c[0] * 8) + 16 for c in P_anchors_all[0]]
    xa = [(c[1] * 8) + 16 for c in P_anchors_all[0]]
    ax.scatter(xa, ya, c="lime", s=25, marker="s", edgecolors="black", linewidths=0.4)
    ax.set_title("Anchor map (replica 0)"); ax.axis("off")

    ax = fig.add_subplot(gs[2, :])
    ax.imshow([W_key], cmap="Greys", aspect="auto")
    ones = W_key.mean() * 100
    ax.set_title(f"256-bit master key | {ones:.1f}% ones "
                 f"({'balanced' if 40 < ones < 60 else 'CHECK SEED'})", fontsize=10)
    ax.set_yticks([])

    plt.suptitle("Registration Diagnostics", fontweight="bold", y=1.01)
    plt.tight_layout()
    path = os.path.join(config.DIAGNOSTICS_DIR, save_name)
    fig.savefig(path, bbox_inches="tight", dpi=120)
    plt.close(fig)
    print(f"   Diagnostics -> {path}")
    return path


def show_tamper_localisation(original_bgr, suspect_bgr, tamper_map, mad_grid,
                              cell_h, cell_w, save_name="tamper_heatmap.png"):
    import matplotlib.patches as patches

    oh, ow = original_bgr.shape[:2]
    orig_rgb = cv2.cvtColor(original_bgr, cv2.COLOR_BGR2RGB)
    susp_r = cv2.resize(suspect_bgr, (ow, oh)) if suspect_bgr.shape[:2] != (oh, ow) else suspect_bgr.copy()
    susp_rgb = cv2.cvtColor(susp_r, cv2.COLOR_BGR2RGB)
    grid = tamper_map.shape[0]
    n_t = int(tamper_map.sum())

    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    axes[0].imshow(orig_rgb); axes[0].set_title("Recovered Original", fontsize=13, fontweight="bold"); axes[0].axis("off")
    axes[1].imshow(susp_rgb)
    axes[1].set_title(f"Suspect - {n_t} flagged region(s)" if n_t > 0 else "Suspect - no regions flagged",
                       fontsize=13, fontweight="bold", color="crimson" if n_t > 0 else "green")
    axes[1].axis("off")
    for gr in range(grid):
        for gc in range(grid):
            if tamper_map[gr, gc]:
                axes[1].add_patch(patches.Rectangle((gc * cell_w, gr * cell_h), cell_w, cell_h,
                                                      linewidth=2, edgecolor="red", facecolor="red", alpha=0.25))
                axes[1].add_patch(patches.Rectangle((gc * cell_w, gr * cell_h), cell_w, cell_h,
                                                      linewidth=2, edgecolor="red", facecolor="none"))
    im = axes[2].imshow(mad_grid, cmap="hot", interpolation="nearest")
    axes[2].set_title(f"MAD heatmap (floor={config.MAD_ABS_FLOOR})", fontsize=13, fontweight="bold")
    plt.colorbar(im, ax=axes[2], label="Mean abs pixel diff")
    plt.suptitle("TAMPER LOCALISATION REPORT", fontsize=15, fontweight="bold", color="crimson", y=1.01)
    plt.tight_layout()
    save_path = os.path.join(config.HEATMAPS_DIR, save_name)
    plt.savefig(save_path, bbox_inches="tight", dpi=150)
    plt.close()
    print(f"   Heatmap saved -> {save_path}")
    return save_path
