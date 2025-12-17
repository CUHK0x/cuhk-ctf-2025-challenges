import {
  useEffect,
  useRef,
  type Dispatch,
  type MouseEvent,
  type SetStateAction,
} from "react";
import {
  BoardGadget,
  ButtonGadget,
  ImageGadget,
  InputGadget,
  TextGadget,
  type Gadget,
} from "~/classes/Gadgets";
import * as utils from "~/utils";

export default function Draggable({
  gadget: gadget,
  mouseDownHandler,
  setCurrentGadget,
  childLoaded,
}: {
  gadget: Gadget;
  mouseDownHandler: (event: MouseEvent<HTMLDivElement>, id: string) => void;
  setCurrentGadget: Dispatch<SetStateAction<string | null>>;
  childLoaded: boolean;
}) {
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    if (gadget instanceof BoardGadget || !iframeRef.current?.contentWindow)
      return;
    if (!childLoaded) return;

    utils.functions.sendToChild(iframeRef.current.contentWindow, {
      isChildBoard: true,
    });
  }, [childLoaded]);

  return (
    <div
      className="fixed"
      style={{ top: gadget.top, left: gadget.left }}
      onMouseDown={(event) => mouseDownHandler(event, gadget.id)}
      onMouseUp={() => setCurrentGadget(null)}
    >
      {gadget instanceof TextGadget && (
        <div className="px-3 py-2 border select-none">{gadget.content}</div>
      )}
      {gadget instanceof InputGadget && (
        <input placeholder={gadget.placeholder} className="border px-3 py-2" />
      )}
      {gadget instanceof ButtonGadget && <button>{gadget.label}</button>}
      {gadget instanceof ImageGadget && (
        <img
          src={gadget.src}
          alt=""
          className="border"
          style={{ width: gadget.width, height: gadget.height }}
        />
      )}
      {gadget instanceof BoardGadget && (
        <iframe
          ref={iframeRef}
          src={new URL(gadget.boardId, import.meta.env.VITE_ROOT_URL).href}
          width={500}
          height={500}
        />
      )}
    </div>
  );
}
