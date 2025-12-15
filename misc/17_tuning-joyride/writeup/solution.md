# TL;DR
The car drives around the outline of a character. Using the two buttons on the screen, the user can switch the path of the car over to other characters of the message. The sequence of characters form the message, with the flag in the message.

# Code Structure
The code contains a minimal html file, bundled js, css and resource files. The vite `svg` logo is also included which indicates it might be developed with Vite, but it is not important.

Looking at the js file, we can see most of the file is occupied by a bunch of data in the same format: (Shortened for brevity)
```js
i:JSON.parse('[["🚦",1470],["🔃",889],["🔀",651],["⬅️",788],...
```
```js
s:JSON.parse("[31.5,-9.5,50,-35.5,51,32,96.5,63.5,0,-222,0,0,108,97,112,0,0,18,12,30.5,317,...
```
```js
m:{"⤵️":"♾️","▶️":"🚀","➡️":"↔️","🪝":"⤵️",...
```

Having such properly structured data and full of emojis, one can make a reasonable guess that this is probably the data of concern-- the data that powers the UI displayed.

The code that follows the data looks like this:
```
class e{x;y;constructor(t,e){this.x=t,this.y=e}translate(t){return new e(this.x+t.x,this.y+t.y)}rotate(t){let s=this.distanceFromOrigin(),i=Math.atan2(-this.y,this.x);return i+=t,new e(s*Math.cos(i),-s*Math.sin(i))}distanceFromOrigin(){return Math.sqrt(this.x**2+this.y**2)}}class s{p0;p1;constructor(t,e){this.p0=t,this.p1=e}static f=(t,e,s)=>e+t*(s-e);...
```
Which has familiar names like `rotate`, `translate` and have less networking jargon compared to the code at the start of the JS file, so we can guess this is the custom code that is written and is of interest. 

There is only a small amount of custom CSS written and has nothing important. The rest of the CSS file is for Bootstrap Icons.

# Code Operation
After reverse engineering the code, one can see that the code basically reads the data mentioned above and renders the animation seen on the UI. Specifically it goes through these steps:
1. Loads the JSON data.
2. Load the instruction and its corresponding data.
3. Translate it into respective SVG commands.
4. Transform the SVG commands to look like the car is moving along the path (whether it actually looks like it is up for debate)
5. Draw the SVG commands to the canvas
6. Repeat the steps to form an animation.

# Interpreting the data
Upon careful inspection, one can probably guess that the paths sketch out the outline of a *glyph*, which is the visual representation of a character in a certain font. The question then becomes "how to transform the paths into characters we can read".

Again, by reverse engineering the code, we can see that the data is structured into three parts:
- `i` for instruction, the first element is the instruction that roughly translates to an SVG path command, the second element indicates the index of the arguments.
- `s` for segments, which is the arguments for the instructions. They are in chunks of four, with commands that take less than four numbers padded with zeros.
- `m` for mapping, which is a mapping to decode the instruction. Each instruction in `i` is resolved by dereferencing it in this mapping, until we found one that maps to itself. The mapping is a collection of multiple *trees*, guaranteed to always resolve to a single command.

The commands roughly translate to SVG path commands, so one can translate the data to SVG without using the code provided after understanding the existing code. Here is a snippet of TypeScript that shows how the instructions map to SVG path commands:

```ts
const commands: Command[] = [
    {name: 'start', cmd: '🚦', aliases: ['🚀', '▶️', '▶', '👉', '📢', '🚥', '🚩']}, // starting point, triggers actions same as move to but used as marker to find start of circuit
    {name: 'line', cmd: '↔️', aliases: ['⬆️', '↗️', '➡️', '↘️', '⬇️', '↙️', '⬅️', '↖️', ]}, // line to
    {name: 'move', cmd: '🚗', aliases: ['🚓', '🚃', '🏎️', '🚔', '🚘', '🚙', '🚛', '🚕', '🚚']}, // move to
    {name: 'curve', cmd: '♾️', aliases: ['↪️', '↩️', '⤴️', '⤵️', '🔃', '🔀', '🪝']}, // quadratic bezier curve to
    {name: 'lap', cmd: '⏱️', aliases: ['⏱', '⭕', '🔁']}, // close path
    {name: 'finish', cmd: '🏁', aliases: ['⏹️', '🛑', '✋', '🖐️', ]}, // signals to go back to the starting point, does not map to any SVG path command
];
```
[src/obfuscated/encoder.ts:12](../src/src/obfuscated/encoder.ts)

Between every `start` and `finish` instruction are paths that encode exactly one character. We can then split the instruction into characters and decode them one by one.

# Decoding the data
But directly translating the instructions one-to-one to SVG commands won't work. This is because **the arguments in SVG commands use absolute coordinates, while the points in each instruction are relative to the starting point** (i.e. as if the starting point of the segment is (0, 0)). Therefore the arguments of the instructions need to be added with the current point.

Another point to note is the large number of commands. But under more observation, one can find that **the instructions are repeated**. That means that the segments are reused. Once we decoded that a sequence corresponds to a specific character, we can reuse this result in the instructions that follows.

# Result
After decoding the entire message, it will be that of the `message` variable in `generateData.ts`, without whitespaces. This is okay since there is no whitespaces in the flag.

Flag: `cuhk25ctf{listen+2+Me+Samir_Y0U_ARE_BREAKING_THE_CAR!!!}`