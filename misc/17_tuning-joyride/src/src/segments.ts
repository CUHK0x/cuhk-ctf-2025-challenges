export class Point {
    x: number;
    y: number;
    constructor(x: number, y: number) {
        this.x = x;
        this.y = y;
    }
    /**
     * Translate a point in 2D coordinate space
     * @param p Vector to translate
     * @returns New point after translation
     */
    tran2d(p: Point): Point {
        return new Point(this.x + p.x, this.y + p.y);
    }
    /**
     * Rotate the point about its origins
     * @param a Angle to rotate, in radians
     * @returns New point after rotation
     */
    rot(a: number): Point {
        let d = this.distanceFromOrigin(), theta = Math.atan2(-this.y, this.x);
        theta += a;
        return new Point(d * Math.cos(theta), -d * Math.sin(theta));
    }
    /**
     * Get the euclidian distance from origin.
     * @returns 
     */
    distanceFromOrigin(): number {
        return Math.sqrt(this.x ** 2 + this.y ** 2);
    }
}

// Representing an imaginary traveller on a curve segment.
// Implement quadratic beizer curve only for testing.
export interface BezierCurve {
    pointAt(s: number): Point;
    derivativeAt(s: number): Point;
    tran2d(s: Point): BezierCurve;
    rot(a: number): BezierCurve;
    path2d(): Path2D;
    controlPoints(): Point[];
}

export class Line implements BezierCurve {
    p0: Point;
    p1: Point;
    constructor(p0: Point, p1: Point) {
        this.p0 = p0;
        this.p1 = p1;
    }
    static f = (s: number, n0: number, n1: number) => n0 + s * (n1 - n0);
    static f_ds = (n0: number, n1: number) => n1 - n0;
    pointAt(s: number): Point {
        return new Point(
            Line.f(s, this.p0.x, this.p1.x),
            Line.f(s, this.p0.y, this.p1.y),
        );
    }
    derivativeAt(_: number): Point {
        return new Point(
            Line.f_ds(this.p0.x, this.p1.x),
            Line.f_ds(this.p0.y, this.p1.y),
        );
    }
    tran2d(s: Point): BezierCurve {
        return new Line(this.p0.tran2d(s), this.p1.tran2d(s));
    }
    rot(a: number): BezierCurve {
        return new Line(this.p0.rot(a), this.p1.rot(a));
    }
    path2d(): Path2D {
        let path = new Path2D();
        path.moveTo(this.p0.x, this.p0.y);
        path.lineTo(this.p1.x, this.p1.y);
        return path;
    }
    controlPoints(): Point[] {
        return [this.p0, this.p1];
    }
}

export class QuadBezier implements BezierCurve {
    p0: Point;
    p1: Point;
    p2: Point;
    constructor(p0: Point, p1: Point, p2: Point) {
        this.p0 = p0;
        this.p1 = p1;
        this.p2 = p2;
    }
    static f = (s: number, n0: number, n1: number, n2: number) => n1 + ((1 - s) ** 2) * (n0 - n1) + (s ** 2) * (n2 - n1);
    static f_ds = (s: number, n0: number, n1: number, n2: number) => 2 * (1 - s) * (n1 - n0) + 2 * s * (n2 - n1); // d(x or y) / ds function.
    pointAt(s: number): Point {
        return new Point(
            QuadBezier.f(s, this.p0.x, this.p1.x, this.p2.x),
            QuadBezier.f(s, this.p0.y, this.p1.y, this.p2.y),
        );
    }
    derivativeAt(s: number): Point {
        return new Point(
            QuadBezier.f_ds(s, this.p0.x, this.p1.x, this.p2.x),
            QuadBezier.f_ds(s, this.p0.y, this.p1.y, this.p2.y),
        );
    }
    tran2d(s: Point): BezierCurve {
        return new QuadBezier(
            this.p0.tran2d(s),
            this.p1.tran2d(s),
            this.p2.tran2d(s),
        )
    }
    rot(a: number): BezierCurve {
        return new QuadBezier(
            this.p0.rot(a),
            this.p1.rot(a),
            this.p2.rot(a),
        )
    }
    path2d(): Path2D {
        let path = new Path2D();
        path.moveTo(this.p0.x, this.p0.y);
        path.quadraticCurveTo(this.p1.x, this.p1.y, this.p2.x, this.p2.y);
        return path;
    }
    controlPoints(): Point[] {
        return [this.p0, this.p1, this.p2];
    }
}