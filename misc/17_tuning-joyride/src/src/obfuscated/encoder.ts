import { type Instruction, type GameData } from "./dto";
import seedrandom from "seedrandom";
import { type Font } from "fontkit";

type Command = {name: string, cmd: string, aliases: string[]};

// This is an array instead of object with `start`, `line`, ... members because
// we cannot loop over properties with type safety in typescript
const commands: Command[] = [
    {name: 'start', cmd: '🚦', aliases: ['🚀', '▶️', '▶', '👉', '📢', '🚥', '🚩']}, // starting point, triggers actions same as move to but used as marker to find start of circuit
    {name: 'line', cmd: '↔️', aliases: ['⬆️', '↗️', '➡️', '↘️', '⬇️', '↙️', '⬅️', '↖️', ]}, // line to
    {name: 'move', cmd: '🚗', aliases: ['🚓', '🚃', '🏎️', '🚔', '🚘', '🚙', '🚛', '🚕', '🚚']}, // move to
    {name: 'curve', cmd: '♾️', aliases: ['↪️', '↩️', '⤴️', '⤵️', '🔃', '🔀', '🪝']}, // quadratic bezier curve
    {name: 'lap', cmd: '⏱️', aliases: ['⏱', '⭕', '🔁']}, // close path
    {name: 'finish', cmd: '🏁', aliases: ['⏹️', '🛑', '✋', '🖐️', ]},
];

// Returns a random integer from [start, end).
function getRandom(rng: seedrandom.PRNG, start: number, end: number): number {
    return Math.floor(rng() * (end - start) + start);
}

function chooseRandom<T>(a: Array<T>, rng: seedrandom.PRNG) {
    const idx = getRandom(rng, 0, a.length);
    console.assert(idx >= 0 && idx < a.length, "Random number should be in array index range.");
    return a[idx];
}

function swapAtIdx<T>(a: Array<T>, idx_a: number, idx_b: number) {
    [a[idx_a], a[idx_b]] = [a[idx_b], a[idx_a]];
}

function shuffleArray<T>(a: Array<T>, rng: seedrandom.PRNG): Array<T> {
    for (var i = 0; i < a.length - 1; i++) {
        const idx = getRandom(rng, i, a.length);
        const t = a[i];
        a[i] = a[idx];
        a[idx] = t;
    }
    return a;
}

/**
 * Encodes Bezier Curves to a custom dto from a font and a text file.
 * Recycles strokes of the same character.
 * Assumes that no glyphs uses the bezierCurveTo command.
 */
export function encodeCircuitsFromFonts(font: Font, text: string, seed?: string, scale: number = 1): GameData {
    // get the glyph of each character as path commands
    const charsetArray = [...new Set(text)];
    const pathCmds = charsetArray.map(char => {
        const glyphs = font.layout(char).glyphs;
        console.assert(glyphs.length == 1); // One character should only have one glyph
        // console.log(glyphs[0].path.toSVG());
        return glyphs[0].path.commands;
    });
    // Scale the points
    pathCmds.map(cmds => cmds.map(cmd => {
        switch (cmd.command) {
            case "moveTo":
            case "lineTo":
            case "quadraticCurveTo":
                cmd.args = cmd.args.map(x => scale * x);
                return cmd;
            case "closePath":
                break;
            case "bezierCurveTo":
                throw new Error;
        }
    }));
    // prepare the array of instructions for each char
    const rng = seedrandom(seed);
    // flatten all the segments of circuits into one array
    // expected: [[x1, y1, x2, y2], [x1, y1, x2, y2], ...]
    // each pathcommand must correspond to one set of arguments, so we put filler for closePath
    let lastEnding = [0, 0];
    const data = pathCmds.flatMap(cmds => 
        cmds.map(cmd => {
            let out: number[];
            switch (cmd.command) {
                case "moveTo":
                case "lineTo":
                    console.assert(cmd.args.length == 2 && cmd.args.every(x => x !== null));
                    out = [cmd.args[0]-lastEnding[0], cmd.args[1]-lastEnding[1], 0, 0];
                    lastEnding = [cmd.args[0], cmd.args[1]];
                    return out;
                case "quadraticCurveTo":
                    console.assert(cmd.args.length == 4 && cmd.args.every(x => x !== null));
                    out = [cmd.args[0]-lastEnding[0], cmd.args[1]-lastEnding[1], cmd.args[2]-lastEnding[0], cmd.args[3]-lastEnding[1]];
                    lastEnding = [cmd.args[2], cmd.args[3]];
                    return out;
                case "closePath":
                    // close path != end of circuit!
                    lastEnding = [0, 0];
                    return [108, 97, 112, 0]; // arbitrary ('lap\0')
                case "bezierCurveTo":
                    throw Error("Unsupported!");
            }
        })
    );
    console.assert(data.every(chunk => chunk.every(x => x !== null)));
    // create an array of consecutive numbers
    const idxArray = Array.from({length: data.length}, (_, k) => k);
    // shuffle the elements and the index at the same time
    console.assert(data.length === idxArray.length);
    for (let i = data.length-1; i > 0; i--) {
        const shuffleIdx = getRandom(rng, 0, i + 1);
        console.assert(shuffleIdx >= 0 && shuffleIdx <= i);
        swapAtIdx(data, idxArray[i], idxArray[shuffleIdx]);
        swapAtIdx(idxArray, i, shuffleIdx);
    }
    // flatten the array
    // construct a mapping tree to decode available commands
    const cmdMap = new Map<string, string>();
    for (const cmd of commands) {
        const choice = [cmd.cmd];
        cmdMap.set(cmd.cmd, cmd.cmd);
        for (const alias of cmd.aliases) {
            cmdMap.set(alias, chooseRandom(choice, rng));
            choice.push(alias);
        }
    }
    const getCommandSymbol = (name: string): string => {
        const tgtCommand = commands.find(cmd => cmd.name === name)!;
        return chooseRandom([tgtCommand.cmd, ...tgtCommand.aliases], rng);
    }
    // Collect the instruction set for each character
    let processed = 0;
    const instructions = pathCmds.map((cmds, i): Instruction[] =>
        [...cmds.map((pathCmd, j): Instruction => {
            // assert that the first one must be move to, as we use start as a
            // moveTo
            if (j == 0) {
                console.assert(pathCmd.command == 'moveTo', "First path command of each glyph should be moveTo");
                return [getCommandSymbol('start'), idxArray[processed++]];
            }
            const pathCmdToCmd = new Map<string, string>([
                ['lineTo', 'line'],
                ['moveTo', 'move'],
                ['quadraticCurveTo', 'curve'],
                ['closePath', 'lap'],
            ]);
            const cmdName = pathCmdToCmd.get(pathCmd.command);
            if (cmdName === undefined) throw Error(`Received unsupported command ${pathCmd.command}, ${j}th path command of ${i+1}th character`);
            return [getCommandSymbol(cmdName), idxArray[processed++]];
        }), [getCommandSymbol('finish'), 0]] // hack: add a finish command to each character. do not increment `processed` to maintain sequential order.
    );
    // Construction mapping of character to instruction set
    const charToInstructions = new Map<string, Instruction[]>;
    console.assert(charsetArray.length === instructions.length, "Each character should have one instruction set.");
    for (var i = 0; i < charsetArray.length; i++) {
        charToInstructions.set(charsetArray[i], instructions[i]);
    }
    return {
        i: Array.from(text).map(ch => charToInstructions.get(ch)!).flat(),
        s: data.flat(),
        m: shuffleArray(Array.from(cmdMap.entries()), rng),
    }
}