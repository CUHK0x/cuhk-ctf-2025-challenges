import {
  useCallback,
  useEffect,
  useState,
  type MouseEvent,
  type MouseEventHandler,
} from "react";
import Draggable from "./components/Draggable";
import { useParams } from "react-router";
import type { Route } from "./+types/Whiteboard";
import * as utils from "~/utils";
import { Gadget, GadgetType, type GadgetData } from "~/classes/Gadgets";
import type { AxiosError } from "axios";
import { v4 as uuidv4 } from "uuid";

export function meta({}: Route.MetaArgs) {
  return [
    { title: "Whiteboard" },
    { name: "description", content: "Feel free to play with the gadgets!" },
  ];
}

function updateBoard(id: string, gadgets: { [id: string]: GadgetData }) {
  utils.objects.APIInstance.put(`/board/${id}`, { content: gadgets });
}

function constructGadget(typeString: GadgetType, data: any): Gadget {
  let gadgetClass: any = utils;
  for (let str of typeString.split(".")) gadgetClass = gadgetClass[str];
  return new gadgetClass(data);
}

export default function Whiteboard() {
  const { id } = useParams();
  const [currentGadget, setCurrentGadget] = useState<string | null>(null);
  const [fetching, setFetching] = useState(true);
  const [fetchError, setFetchError] = useState<AxiosError | null>(null);
  const [offset, setOffset] = useState({ x: 0, y: 0 });

  const [gadgets, setGadgets] = useState<{ [id: string]: GadgetData }>({});

  const mouseDownHandler = useCallback(
    (event: MouseEvent<HTMLDivElement>, id: string) => {
      setCurrentGadget(id);

      const boundingRect = event.currentTarget.getBoundingClientRect();
      const relativeX = event.clientX - boundingRect.left;
      const relativeY = event.clientY - boundingRect.top;

      setOffset({ x: relativeX, y: relativeY });
    },
    [],
  );

  const mouseMoveHandler = useCallback<MouseEventHandler<HTMLDivElement>>(
    (event) => {
      if (!currentGadget) return;

      const targetX = event.clientX - offset.x;
      const targetY = event.clientY - offset.y;

      setGadgets((prev) => ({
        ...prev,
        [currentGadget]: {
          ...prev[currentGadget],
          left: targetX,
          top: targetY,
        },
      }));
      event.currentTarget.style.left = `${targetX}px`;
      event.currentTarget.style.top = `${targetY}px`;
    },
    [currentGadget, offset],
  );

  const [childLoaded, setChildLoaded] = useState(false);
  const [isChild, setIsChild] = useState(false);

  useEffect(() => {
    utils.functions.handleMessages((event) => {
      if (event.origin !== window.origin) return;
      const { data } = event;
      if (data.pageLoaded) setChildLoaded(true);
      if (data.isChildBoard) setIsChild(true);
      if (data.executeFunction) {
        try {
          new Function(data.functionString)(...data.arguments);
        } catch (error) {
          console.error(error);
        }
      }
    });

    if (document.readyState === "complete")
      utils.functions.sendToParent({ pageLoaded: true });
    else
      window.addEventListener("load", () =>
        utils.functions.sendToParent({ pageLoaded: true }),
      );

    utils.objects.APIInstance.get(`/board/${id}`)
      .then((res) => {
        setGadgets(res.data.board.content);
        setFetchError(null);
      })
      .catch((error: AxiosError) => {
        console.error(error);
        setFetchError(error);
      })
      .finally(() => setFetching(false));
  }, []);

  useEffect(() => {
    if (id === undefined) return;

    const timeout = window.setTimeout(() => {
      updateBoard(id, gadgets);
    }, 500);

    return () => window.clearTimeout(timeout);
  }, [gadgets]);

  return (
    <div className="w-screen h-screen border-4" onMouseMove={mouseMoveHandler}>
      {isChild && <div>CHILD</div>}
      <div
        className="fixed bottom-8 right-8 px-4 py-2 bg-white border border-gray-300 rounded-lg shadow-md cursor-pointer select-none text-black"
        onClick={() => {
          const id = uuidv4();
          setGadgets((prev) => ({
            ...prev,
            [id]: {
              id,
              type: GadgetType.PARAGRAPH,
              content: "New Gadget",
              left: Math.floor(Math.random() * window.innerWidth * 0.8),
              top: Math.floor(Math.random() * window.innerHeight * 0.8),
            },
          }));
        }}
      >
        Add Gadget
      </div>
      {fetching ? (
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-gray-400">
          Loading...
        </div>
      ) : !fetchError ? (
        Object.values(gadgets).map((data) => {
          const gadget = constructGadget(data.type, data);
          return (
            <Draggable
              {...{ gadget, mouseDownHandler, setCurrentGadget, childLoaded }}
              key={data.id}
            />
          );
        })
      ) : (
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-red-400">
          <div>Error fetching board data.</div>
          <div>{fetchError.message}</div>
        </div>
      )}
    </div>
  );
}
