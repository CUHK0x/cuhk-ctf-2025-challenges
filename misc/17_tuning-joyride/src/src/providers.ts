import type { BezierCurve } from './segments';
import { Line, Point, QuadBezier } from './segments';

export abstract class CircuitProvider {
    idx: number = 0;
    normalizedSegments: BezierCurve[] = [];
    nextSegment(): BezierCurve {
        let t = this.normalizedSegments[this.idx++];
        if (this.idx == this.normalizedSegments.length) this.idx = 0;
        return t;
    }
}

export type PointDto = { x: number, y: number };
export type CurveDto = {
    type: 'l';
    cp: { p0: PointDto, p1: PointDto };
} | {
    type: 'q';
    cp: { p0: PointDto, p1: PointDto, p2: PointDto };
}

export type Circuit = CurveDto[];

export class StandardCircuitLoader extends CircuitProvider {
    private static loadPoint(p: PointDto): Point {
        return new Point(p.x, p.y);
    }
    private static loadCurve(curve: CurveDto): BezierCurve {
        switch (curve.type) {
            case 'l':
                return new Line(
                    StandardCircuitLoader.loadPoint(curve.cp.p0),
                    StandardCircuitLoader.loadPoint(curve.cp.p1),
                );
            case 'q':
                return new QuadBezier(
                    StandardCircuitLoader.loadPoint(curve.cp.p0),
                    StandardCircuitLoader.loadPoint(curve.cp.p1),
                    StandardCircuitLoader.loadPoint(curve.cp.p2),
                );
        }
    }
    constructor(curves: CurveDto[]) {
        super();
        let p = new Point(0, 0);
        this.normalizedSegments = curves.map(
            data => {
                const c = StandardCircuitLoader.loadCurve(data).tran2d(p);
                p = c.controlPoints().at(-1)!;
                return c;
            }
        );
    }
}