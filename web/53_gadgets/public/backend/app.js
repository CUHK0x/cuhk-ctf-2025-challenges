const express = require("express");
const { json } = require("express");
const cors = require("cors");
const { createBoard, getBoard, updateBoard } = require("./controller/board");
const { visit } = require("./controller/visit");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const { rateLimit } = require("express-rate-limit");

const app = express();
app.use([json(), cors()]);

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  limit: 1,
  message: { message: "Too many requests, please try again later." },
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

app.get("/status", (req, res) => {
  return res.json({ status: "ok" });
});

const verifyBoardId = async (req, res, next) => {
  const id = req.params?.id;

  if (!id) return res.status(401).json({ message: "Board ID is required." });

  try {
    const board = await prisma.board.findUnique({
      where: { id },
    });

    if (!board) return res.status(404).json({ message: "Board not found" });

    req.boardId = id;
    next();
  } catch (err) {
    res.status(400).json({ message: "Invalid ID" });
  }
};

app.post("/board", createBoard);
app.get("/board/:id", verifyBoardId, getBoard);
app.put("/board/:id", verifyBoardId, updateBoard);

app.post("/visit", limiter, visit);
