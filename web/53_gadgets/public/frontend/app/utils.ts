import axios from "axios";
import {
  BoardGadget,
  ButtonGadget,
  ImageGadget,
  InputGadget,
  TextGadget,
} from "./classes/Gadgets";

const APIInstance = axios.create({ baseURL: import.meta.env.VITE_API_URL });

function sendToParent(payload: any) {
  if (window.top === window) return;
  window.parent.postMessage(payload);
}

function sendToChild(childWindow: Window, payload: any) {
  childWindow.postMessage(payload);
}

function handleMessages(
  handler: Parameters<typeof window.addEventListener<"message">>[1],
) {
  window.addEventListener("message", handler);
}

export const gadget = {
  paragraph: TextGadget,
  text_input: InputGadget,
  button: ButtonGadget,
  image: ImageGadget,
  board: BoardGadget,
};

export const functions = {
  sendToChild,
  sendToParent,
  handleMessages,
};

export const objects = { APIInstance };
