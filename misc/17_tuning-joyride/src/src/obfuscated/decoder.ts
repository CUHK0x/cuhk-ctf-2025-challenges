import { CircuitProvider } from "../providers";
import { Line, Point, QuadBezier, type BezierCurve } from "../segments";
import type { GameData } from "./dto";

export class ObfuscatedDataLoader extends CircuitProvider {
    gameData: GameData;
    idx: number = 0;
    startingPoint?: Point;
    resolveTable: Map<string, string>;
    current?: Point;
    constructor(data: GameData) {
        super();
        this.gameData = data;
        this.resolveTable = new Map<string, string>(data.m);
    }
    backPC() {
        this.idx--;
        if (this.idx < 0) this.idx = this.gameData.i.length - 1;
    }
    stepPC() {
        this.idx++;
        if (this.idx == this.gameData.i.length) this.idx = 0;
    }
    decodeIns(s: string): string {
        const val = this.resolveTable.get(s)!;
        if (s === val) return val;
        return this.decodeIns(val);
    }
    nextCircuit() {
        do {
            this.stepPC();
        } while (this.decodeIns(this.gameData.i[this.idx][0]) != '🚦')
    }
    prevCircuit() {
        do {
            this.backPC();
        } while (this.decodeIns(this.gameData.i[this.idx][0]) != '🚦')
    }
    nextSegment(): BezierCurve {
        const ins = this.gameData.i[this.idx];
        const args = this.gameData.s.slice(ins[1] * 4, (ins[1] + 1) * 4);
        let nextCurve: BezierCurve;
        switch(this.decodeIns(ins[0])) {
            case '🚦':
            case '🚗':
                if (!this.startingPoint) this.startingPoint = new Point(args[0], args[1]);
                this.current = new Point(args[0], args[1]);
                this.stepPC();
                return this.nextSegment();
            case '↔️':
                if (!this.current) throw new Error();
                const nextPoint = (new Point(args[0], args[1])).tran2d(this.current);
                nextCurve = new Line(this.current, nextPoint);
                this.current = nextPoint;
                break;
            case '♾️':
                if (!this.current) throw new Error();
                const p1 = (new Point(args[0], args[1])).tran2d(this.current);
                const p2 = (new Point(args[2], args[3])).tran2d(this.current);
                nextCurve = new QuadBezier(this.current, p1, p2);
                this.current = p2;
                break;
            case '⏱️':
                if (!this.current || !this.startingPoint) throw new Error();
                nextCurve = new Line(this.current, this.startingPoint);
                this.current = this.startingPoint;
                this.startingPoint = undefined;
                break;
            case '🏁':
                // Cycle backwards
                do this.backPC()
                while (this.decodeIns(this.gameData.i[this.idx][0]) != '🚦');
                return this.nextSegment();
            default:
                throw new Error();
        }
        this.stepPC();
        return nextCurve;
    }
}