const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

exports.createBoard = async (req, res) => {
  try {
    const board = await prisma.board.create({ data: {} });
    return res.status(201).json({ board });
  } catch (error) {
    return res.status(500).json({ message: "Error creating board", error });
  }
};

exports.getBoard = async (req, res) => {
  const board = await prisma.board.findUnique({
    where: { id: req.boardId },
  });

  if (!board) return res.status(404).json({ message: "Board not found" });

  return res.status(200).json({ board });
};

exports.updateBoard = async (req, res) => {
  const id = req.boardId;
  const { content } = req.body;

  if (!content) {
    return res.status(400).json({ message: "Content is required" });
  }

  try {
    const updatedBoard = await prisma.board.update({
      where: { id },
      data: { content },
    });
    return res.status(200).json({ board: updatedBoard });
  } catch (error) {
    return res.status(500).json({ message: "Error updating board", error });
  }
};
