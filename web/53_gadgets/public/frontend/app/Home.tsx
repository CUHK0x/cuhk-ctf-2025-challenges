import { useState } from "react";
import { useNavigate } from "react-router";
import * as utils from "~/utils";

export default function Init() {
  const navigate = useNavigate();

  const [loading, setLoading] = useState(false);
  const [visiting, setVisiting] = useState(false);
  const [visitUrl, setVisitUrl] = useState("");

  const createBoard = () => {
    setLoading(true);
    utils.objects.APIInstance.post("/board")
      .then((res) => {
        if (res.status !== 201) throw new Error(res.data.message);
        navigate(res.data.board.id);
      })
      .catch((err) => {
        console.error(err);
        setLoading(false);
      });
  };

  const adminVisit = () => {
    setVisiting(true);
    utils.objects.APIInstance.post("/visit", { dest: visitUrl })
      .then((res) => {
        alert(res.data.message);
        setVisiting(false);
      })
      .catch((error) => {
        console.error(error);
        alert(error.response?.data?.message || error.message);
        setVisiting(false);
      });
  };

  return (
    <div className="w-screen h-screen flex flex-col justify-center items-center gap-4">
      <div className="text-3xl font-bold">Welcome to my Whiteboard App!</div>
      <div className="text-lg">
        We have a lot of gadgets for you to play around with. Have fun!
      </div>
      <div className="flex gap-2 items-center mt-12">
        <button
          onClick={createBoard}
          disabled={loading}
          className="px-4 py-2 bg-blue-500 text-white rounded cursor-pointer disabled:opacity-50"
        >
          {loading ? "Creating..." : "Create new board"}
        </button>
        <div className="text-lg">OR</div>
        <div className="flex gap-2 items-center flex-col">
          <input
            placeholder="Enter URL for admin to visit"
            onChange={(e) => setVisitUrl(e.target.value)}
            className="border p-2 rounded w-96 placeholder:text-center disabled:opacity-50"
            value={visitUrl}
            disabled={visiting}
          />
          <button
            onClick={adminVisit}
            disabled={visiting}
            className="px-4 py-2 bg-green-500 text-white rounded cursor-pointer disabled:opacity-50"
          >
            {visiting ? "Admin Visiting..." : "Ask Admin to Visit"}
          </button>
        </div>
      </div>
    </div>
  );
}
