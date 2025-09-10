-- CreateTable
CREATE TABLE "public"."System" (
    "id" TEXT NOT NULL,
    "nameth" TEXT,
    "nameEng" TEXT,
    "shortName" TEXT,
    "url" TEXT,
    "bgColor" TEXT,
    "borderColor" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "System_pkey" PRIMARY KEY ("id")
);
