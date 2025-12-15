import './style.css';
import "bootstrap-icons/font/bootstrap-icons.css";
import carUrl from './car.png';
import data from './circuits.json';
import { CircuitTraveller, Engine } from './engine';
import { ObfuscatedDataLoader } from './obfuscated/decoder';
import type { GameData } from './obfuscated/dto';

const canvasId = 'screen';

const canvas = document.getElementById(canvasId) as HTMLCanvasElement;
const loader = new ObfuscatedDataLoader(data as GameData);
const traveller = new CircuitTraveller(loader);
document.getElementById("prev")!.addEventListener('click', () => loader.prevCircuit());
document.getElementById("next")!.addEventListener('click', () => loader.nextCircuit());
const eng = new Engine(canvas, traveller, carUrl);
eng.requestRender();
console.log("%c Nothing to see here...", "color:blue;font-weight:bold");