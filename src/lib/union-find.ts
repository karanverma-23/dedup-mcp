/**
 * Disjoint Set Union (DSU) — used to convert pairwise duplicate decisions
 * into clustered duplicate groups.
 *
 * Standard textbook implementation with path compression and union-by-rank.
 * O(α(N)) amortized per operation.
 */

export class UnionFind<T> {
  private parent = new Map<T, T>();
  private rank = new Map<T, number>();

  add(x: T): void {
    if (!this.parent.has(x)) {
      this.parent.set(x, x);
      this.rank.set(x, 0);
    }
  }

  find(x: T): T {
    this.add(x);
    let root = x;
    while (this.parent.get(root) !== root) {
      root = this.parent.get(root)!;
    }
    let curr = x;
    while (this.parent.get(curr) !== root) {
      const next = this.parent.get(curr)!;
      this.parent.set(curr, root);
      curr = next;
    }
    return root;
  }

  union(a: T, b: T): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra === rb) return;
    const rankA = this.rank.get(ra) ?? 0;
    const rankB = this.rank.get(rb) ?? 0;
    if (rankA < rankB) {
      this.parent.set(ra, rb);
    } else if (rankA > rankB) {
      this.parent.set(rb, ra);
    } else {
      this.parent.set(rb, ra);
      this.rank.set(ra, rankA + 1);
    }
  }

  /** Return all groups (sets of elements sharing a root), keyed by root. */
  groups(): Map<T, T[]> {
    const groups = new Map<T, T[]>();
    for (const x of this.parent.keys()) {
      const root = this.find(x);
      if (!groups.has(root)) groups.set(root, []);
      groups.get(root)!.push(x);
    }
    return groups;
  }
}
