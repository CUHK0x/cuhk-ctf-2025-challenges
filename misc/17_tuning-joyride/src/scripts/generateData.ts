import { fileURLToPath } from "url";
import * as fontkit from 'fontkit';
import { exit } from "process";
import * as fs from 'fs';
import { encodeCircuitsFromFonts } from "../src/obfuscated/encoder";
import * as https from 'https';

// Text that the circuits represent
const flag = "cuhk25ctf{listen+2+Me+Samir_Y0U_ARE_BREAKING_THE_CAR!!!}";
const message = `Hello and welcome to CUHK CTF 2025! I hope you had fun solving challenges. If you have written challenges before, you might know that making challenges are not an easy task. Challenges are like puzzles: we have to scratch our heads off to think where to hide the hints and vulnerabilities, even so do it creatively so that it is entertaining. I would even say this is *the romance of nerds*. I mean, we are not compensated, all of us are writing CTF challenges in our own free time. As they say, \"Generating electricity with love\", amirite? In any case, here is the flag: ${flag} Thanks for solving this challenge! (Hope you didn't sketch every letter out by hand. btw The font is Varela Round, you should be glad I didn't use Wingdings)`;

// Challenge constant, change to get alternative order of export data
// Assert that the webpage will look the same regardless of the choice of this string
const seed = "If in doubt go flat out";

const VARELA_ROUND_URL = 'https://fonts.gstatic.com/s/varelaround/v20/w8gdH283Tvk__Lua32TysjIvoA.ttf';

/**
 * Downloads a file from a URL and saves it to a specified destination path.
 * @param fileUrl The URL of the file to download.
 * @param destPath The local file path to save the downloaded file.
 */
function downloadFile(fileUrl: string, destPath: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
        const fileStream = fs.createWriteStream(destPath);
        https.get(fileUrl, (response) => {
            if (response.statusCode && response.statusCode >= 400) {
                reject(new Error(`Request Failed. Status Code: ${response.statusCode}`));
                response.resume(); // Consume response data to free up memory
                return;
            }

            response.pipe(fileStream);

            fileStream.on('finish', () => {
                fileStream.close();
                resolve();
            });
        }).on('error', (err) => {
            fileStream.close();
            reject(err);
        });
    });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    let fontSource: string;
    let output: string;
    switch(process.argv.length) {
        case 3:
            // Use Varela Round
            fontSource = "./Varela-Round.ttf";
            output = process.argv[2];
            if (!fs.existsSync(fontSource)) {
                await downloadFile(VARELA_ROUND_URL, fontSource);
                console.log(`Downloaded font file to ${fontSource}`);
            }
            break;
        case 4:
            fontSource = process.argv[2];
            output = process.argv[3];
            break;
        default:
            console.log("Usage: tsx generateData.ts <output>");
            console.log("Use default font.\n");
            console.log("Usage: tsx generateData.ts <font> <output>");
            console.log("Use a user-supplied font file.");
            console.log("Generate data to be loaded in the tuning joyride challenge.");
            exit(1);
    }
    // obfuscated mode
    const font = fontkit.openSync(fontSource) as fontkit.Font;
    // remove spaces since they don't generate any path
    console.log("Generating data for message:");
    console.log(message);
    const data = encodeCircuitsFromFonts(font, message, seed, 4);
    console.assert((data.s.length % 4) == 0, "Numbers array is not a multiple of 4!");
    fs.writeFile(output, JSON.stringify(data), err => {
        console.log(err);
    });
}