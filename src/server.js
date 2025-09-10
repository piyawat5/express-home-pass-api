// const express = require('exporess');  common js
/* 
npx prisma init --datasource-provider mysql
npx prisma migrate dev --name init
npx prisma migrate reset
*/

import express from "express";
import cors from "cors";
import morgan from "morgan";
import authen from "./routes/auth.route.js";
import cookieParser from "cookie-parser";

const app = express();
app.use(
  cors({
    origin: "http://localhost:5173", // origin ของ frontend
    credentials: true, // ให้ส่ง cookie/header มาด้วยได้
  })
);
app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());

app.use("/", authen);

app.use((err, req, res, next) => {
  res
    .status(err.code || 500)
    .json({ message: err.message || `something wrong!!!` });
});

const port = 8000;
app.listen(port, () => {
  return console.log(`server running on port ${port}`);
});
