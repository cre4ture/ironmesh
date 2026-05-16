export type ClusterableScreenPoint<T> = {
  id: string;
  x: number;
  y: number;
  item: T;
};

export type ScreenPointCluster<T> = {
  id: string;
  x: number;
  y: number;
  minX: number;
  maxX: number;
  minY: number;
  maxY: number;
  points: ClusterableScreenPoint<T>[];
};

type MutableScreenPointCluster<T> = {
  cellX: number;
  cellY: number;
  xTotal: number;
  yTotal: number;
  minX: number;
  maxX: number;
  minY: number;
  maxY: number;
  points: ClusterableScreenPoint<T>[];
};

export function clusterScreenPoints<T>(
  points: ClusterableScreenPoint<T>[],
  radius: number
): ScreenPointCluster<T>[] {
  if (points.length === 0) {
    return [];
  }

  const safeRadius = Math.max(1, radius);
  const radiusSquared = safeRadius * safeRadius;
  const grid = new Map<string, MutableScreenPointCluster<T>[]>();
  const clusters: MutableScreenPointCluster<T>[] = [];

  for (const point of points) {
    const cellX = Math.floor(point.x / safeRadius);
    const cellY = Math.floor(point.y / safeRadius);
    let bestCluster: MutableScreenPointCluster<T> | null = null;
    let bestDistanceSquared = Number.POSITIVE_INFINITY;

    for (let deltaX = -1; deltaX <= 1; deltaX += 1) {
      for (let deltaY = -1; deltaY <= 1; deltaY += 1) {
        const candidates = grid.get(clusterGridKey(cellX + deltaX, cellY + deltaY));
        if (!candidates) {
          continue;
        }

        for (const candidate of candidates) {
          const centroidX = candidate.xTotal / candidate.points.length;
          const centroidY = candidate.yTotal / candidate.points.length;
          const distanceSquared =
            (point.x - centroidX) * (point.x - centroidX) +
            (point.y - centroidY) * (point.y - centroidY);
          if (distanceSquared > radiusSquared || distanceSquared >= bestDistanceSquared) {
            continue;
          }

          bestCluster = candidate;
          bestDistanceSquared = distanceSquared;
        }
      }
    }

    if (!bestCluster) {
      const nextCluster: MutableScreenPointCluster<T> = {
        cellX,
        cellY,
        xTotal: point.x,
        yTotal: point.y,
        minX: point.x,
        maxX: point.x,
        minY: point.y,
        maxY: point.y,
        points: [point]
      };
      clusters.push(nextCluster);
      const key = clusterGridKey(cellX, cellY);
      const cellClusters = grid.get(key) ?? [];
      cellClusters.push(nextCluster);
      grid.set(key, cellClusters);
      continue;
    }

    bestCluster.points.push(point);
    bestCluster.xTotal += point.x;
    bestCluster.yTotal += point.y;
    bestCluster.minX = Math.min(bestCluster.minX, point.x);
    bestCluster.maxX = Math.max(bestCluster.maxX, point.x);
    bestCluster.minY = Math.min(bestCluster.minY, point.y);
    bestCluster.maxY = Math.max(bestCluster.maxY, point.y);
  }

  return clusters.map((cluster) => {
    const x = cluster.xTotal / cluster.points.length;
    const y = cluster.yTotal / cluster.points.length;
    return {
      id: `${cluster.points[0]?.id ?? "cluster"}:${cluster.points.length}:${Math.round(x)}:${Math.round(y)}`,
      x,
      y,
      minX: cluster.minX,
      maxX: cluster.maxX,
      minY: cluster.minY,
      maxY: cluster.maxY,
      points: cluster.points
    };
  });
}

function clusterGridKey(cellX: number, cellY: number): string {
  return `${cellX}:${cellY}`;
}