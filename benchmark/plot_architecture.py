# SPDX-License-Identifier: MIT
"""Create the versioned local architecture diagram for Figure 1."""
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch


def render(out):
    navy, fill, muted = '#24445e', '#dce8f0', '#61727d'
    fig, ax = plt.subplots(figsize=(11.5, 6.35), dpi=170)
    fig.patch.set_facecolor('white')
    ax.set(xlim=(0, 11.5), ylim=(0, 6.35))
    ax.axis('off')
    ax.text(5.75, 6.05, 'EduChainTrust v1.12.0 local research architecture',
            ha='center', va='center', fontsize=19, fontweight='bold', color=navy)
    ax.text(.45, 5.45, 'Authenticated issue and anchoring', fontsize=13, fontweight='bold', color=muted)
    ax.text(.45, 3.52, 'Trusted verification', fontsize=13, fontweight='bold', color=muted)
    xs = (.45, 3.25, 6.05, 8.85)
    def box(x, y, lines):
        ax.add_patch(FancyBboxPatch((x, y), 2.2, 1.0, boxstyle='round,pad=.05,rounding_size=.14',
                                    edgecolor=navy, facecolor=fill, linewidth=1.8))
        ax.text(x+1.1, y+.5, lines, ha='center', va='center', fontsize=11.3,
                fontweight='bold', color=navy, linespacing=1.2)
    top = ('Issuer token\n(checked path)', 'Active issuer key\n(checked path)',
           'Signed credential\n(active method)', 'SQLite evidence\n(digest + issuer)')
    bottom = ('Verifier token\n(local role)', 'Retained keys\nverify old anchors',
              'Structure + proof\n+ time + evidence', 'Separate flags\n+ aggregate result')
    for x, label in zip(xs, top): box(x, 4.1, label)
    for x, label in zip(xs, bottom): box(x, 2.08, label)
    def arrow(a, b):
        ax.add_patch(FancyArrowPatch(a, b, arrowstyle='-|>', mutation_scale=17,
                                     color=navy, linewidth=2.4))
    for y in (4.6, 2.58):
        for x in xs[:-1]: arrow((x+2.26,y),(x+2.73,y))
    arrow((9.95,4.03),(7.1,3.14))
    ax.add_patch(FancyBboxPatch((.45,.23),10.45,1.05,boxstyle='round,pad=.08,rounding_size=.17',
                                edgecolor=muted,facecolor='white',linewidth=1.5))
    ax.text(5.75,.75,'Separate local demo: Streamlit session  →  ephemeral key  →  MockBlockchain\n'
            'No shared authority or database with the API',ha='center',va='center',
            fontsize=12.3,color=muted)
    fig.savefig(out,dpi=170,facecolor='white')
    plt.close(fig)


if __name__ == '__main__':
    render(Path(__file__).with_name('figure1_v1.12.0.png'))
