/*
  Warnings:

  - You are about to drop the `User` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropTable
DROP TABLE "public"."User";

-- DropEnum
DROP TYPE "public"."Role";

-- CreateTable
CREATE TABLE "public"."Board" (
    "id" SERIAL NOT NULL,
    "content" JSONB NOT NULL,

    CONSTRAINT "Board_pkey" PRIMARY KEY ("id")
);
