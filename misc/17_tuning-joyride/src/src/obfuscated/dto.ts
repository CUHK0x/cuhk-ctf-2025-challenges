// Commands:
// Start: Start a circuit
// Line: A line command
// Curve: A quadratic beizer curve command
// Finish: Ending of a circuit
export type Instruction = [string, number]; // c: command, r: reference

export interface GameData {
    // {start, <undefined>}, {line/curve, idx}, {line/curve, idx}, ... {end, <undefined>}, {start, []}, ...
    i: Instruction[], // index for loading objects
    // [x1, y1, x2, y2, x1, y1, x2, y2, ...]
    s: number[], // segments / strokes of the font
    m: [string, string][], // mapping for modes
}

// each curve is inseparable:
// line defined by a point (two numbers)
// quadratic curve defined by two points (fou
// r values)
// strokes of the font are shuffled, each stroke takes four values.
// Because line only has two values, right pad to four values with random values
// mapping: a large map of modes that resolves into two modes
// a key value pair: keep resolving edges until an edge resolved into itself