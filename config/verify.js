import jwt from "jsonwebtoken";
import createError from "../utils/createError.js";

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return next(createError(401, "No token provided"));
  const token = authHeader.split(" ")[1];
  try {
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
      if (err) {
        createError(401, "token หมดอายุ");
      }
      next();
    });
  } catch (err) {
    next(err);
  }
};

export default verifyToken;
