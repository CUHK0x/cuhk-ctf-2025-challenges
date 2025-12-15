import type { CircuitProvider } from "./providers";
import { Point, type BezierCurve } from "./segments";

/**
 * A machine that moves along a path (i.e. a collection of segments).
 * Has the responsibility to render the paths, including transformation.
 */
export class CircuitTraveller {
    provider: CircuitProvider;
    segments: BezierCurve[];
    s: number = 0;
    constructor(provider: CircuitProvider)  {
        this.provider = provider;
        this.segments = Array.from({length: 5}, () => provider.nextSegment());
    }
    // Transform the paths such that start at 0
    // all path is drawn from current point, in absolute coordinates
    // moveTo(x, y): move pen to (x, y)
    // quadraticCurveTo(x1, y1, x2, y2): move to (x2, y2) with control point (x1, y1)
    // lineTo(x, y): draw line to (x, y)
    // closePath: Move to the starting point in a straight line (at the end of the path)
    /**
     * Increment the traveller to the next point at speed after time dt.
     * @param dt Elapsed time
     * @param speed Speed in px / unit time
     * @returns The new point after stepping, or null if the segment is completed.
     */
    inc(dt: number, speed: number) {
        let ds_dt = speed / this.segments[0].derivativeAt(this.s).distanceFromOrigin();
        this.s += ds_dt * dt;
        if (this.s > 1) {
            // Switch to the next segment
            this.segments.shift();
            this.segments.push(this.provider.nextSegment());
            // ignore the discrepancies and only start at the beginning of the segment
            // cannot s-=1 because variation of s is not proportional to length
            // proper way is to calculate the overflowed length and set s
            // TODO: Fix
            this.s = 0;
        }
    }
    /**
     * Render all paths to context
     * @param ctx Context to render to
     */
    renderTo(ctx: CanvasRenderingContext2D) {
        // move first segment to center at center of screen
        // move the rest of the segments to the end of each ending point
        let path = new Path2D();
        // assert this.segments.length >= 1
        const carCentre = this.segments[0].pointAt(this.s);
        const derivative = this.segments[0].derivativeAt(this.s);
        // Note: assumes all strokes start at 0, 0
        let translateTarget = new Point(-carCentre.x, -carCentre.y);
        for (const seg of this.segments) {
            const finalSeg = seg
                             .tran2d(translateTarget)
                             .rot(Math.PI / 2 - Math.atan2(-derivative.y, derivative.x))
                             .tran2d(new Point(ctx.canvas.width / 2, ctx.canvas.height / 2));
            path.addPath(finalSeg.path2d());
        }
        ctx.stroke(path);
    }
}

export class Engine {
    ctx: CanvasRenderingContext2D; 
    traveller: CircuitTraveller;
    carSprite: HTMLImageElement;
    constructor(canvas: HTMLCanvasElement, traveller: CircuitTraveller, carSpriteUrl: string) {
        this.ctx = canvas.getContext("2d")!;
        this.updateCanvasSize();
        window.addEventListener('resize', () => this.updateCanvasSize());
        this.traveller = traveller;
        this.carSprite = new Image();
        this.carSprite.src = carSpriteUrl;
    }
    len: number = 0;
    prevTimestamp: DOMHighResTimeStamp = 0;
    render(timestamp: DOMHighResTimeStamp) {
        const dt = timestamp - this.prevTimestamp;
        this.prevTimestamp = timestamp;
        this.ctx.clearRect(0, 0, this.ctx.canvas.width, this.ctx.canvas.height);
        // translate origin to that point
        // rotate tangent towards up, requires tangent
        this.traveller.inc(dt, 0.1);
        this.ctx.strokeStyle = '#000000';
        this.ctx.lineWidth = 60;
        this.traveller.renderTo(this.ctx);
        // TODO: Render other visual effects here
        // Draw car
        // TODO: If anyone is interested, can implement curvature formula to
        // add steering animation
        this.ctx.fillStyle = '#FF0000FF';
        const carWidth = this.carSprite.naturalWidth * 0.1;
        const carHeight = this.carSprite.naturalHeight * 0.1;
        this.ctx.drawImage(
            this.carSprite,
            (this.ctx.canvas.width - carWidth) / 2,
            (this.ctx.canvas.height - carHeight) / 2,
            carWidth,
            carHeight,
        );
        // Draw time
        this.ctx.font = "48px monospace";
        const s = `Time: ${(timestamp / 1000).toFixed(3)}s`;
        const textMetrics = this.ctx.measureText(s);
        this.ctx.fillText(s, this.ctx.canvas.width - textMetrics.width - 10, 50);
        this.requestRender();
    }
    private updateCanvasSize() {
        this.ctx.canvas.width = window.innerWidth;
        this.ctx.canvas.height = window.innerHeight;
    }
    aniId?: number;
    requestRender() {
        this.aniId = requestAnimationFrame((ts) => this.render(ts));
    }
}