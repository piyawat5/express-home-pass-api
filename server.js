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
const corsOptions = {
  origin: ["http://localhost:5173", "http://localhost:3000"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  optionsSuccessStatus: 200,
};

// ใช้ CORS middleware ก่อน routes อื่นๆ
app.use(cors(corsOptions));
app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());

app.use("/", authen);

app.use((err, req, res, next) => {
  res
    .status(err.code || 500)
    .json({ message: err.message || `something wrong!!!` });
});

const port = process.env.PORT || 8000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
