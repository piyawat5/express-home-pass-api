import express from "express";
import {
  register,
  login,
  authen,
  refreshAccessToken,
  logout,
  sendOTP,
  verifyOTPAndRegister,
  googleLogin,
  resendOTP,
  dog,
  startGoogleLogin,
  googleCallback,
} from "../controllers/authCookie.controller.js";
import { registerSchema, loginSchema, validate } from "../utils/validator.js";
import verifyToken from "../config/verify.js";
import { preLogLogin } from "../controllers/logUser.controller.js";
const router = express.Router();

// ------------- auth --------------
router.get("/dog", dog);
router.post("/auth/register", validate(registerSchema), register);
router.post("/auth/login", validate(loginSchema), preLogLogin, login);
router.get("/auth/verify", authen);
router.post("/auth/refreshToken", refreshAccessToken);
router.post("/auth/logout", logout);
router.post("/auth/sendOTP", validate(registerSchema), sendOTP);
router.post("/auth/resendOTP", resendOTP);
// TODO: validate
router.post("/auth/verifyOTP", verifyOTPAndRegister);

// OAuth routes old มีปัญหาบนโทรศัพท์
router.post("/auth/googleLogin", googleLogin);

//  OAuth New
router.get("/auth/google", startGoogleLogin);
router.get("/auth/google/callback", googleCallback);

export default router;
