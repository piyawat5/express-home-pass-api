import prisma from "../config/prisma.js";
import createError from "../utils/createError.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import nodemailer from "nodemailer";
import { OAuth2Client } from "google-auth-library";
import axios from "axios";
import { google } from "googleapis";
import { createUserLog } from "../utils/logUser.js";

// ------------------- function -----------------------
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  "https://family-sivarom.com/auth/google/callback" // ต้องตรงกับ Google Console
);

const hashRt = (rt) => crypto.createHash("sha256").update(rt).digest("hex");

const generateAccessToken = (user) => {
  return jwt.sign(
    {
      ...user,
    },
    process.env.JWT_SECRET_KEY,
    { expiresIn: "30m" }
  );
};

const generateRefreshToken = async (user) => {
  const raw = crypto.randomBytes(40).toString("hex");
  const tokenHash = hashRt(raw);
  const expires = new Date(Date.now() + 60 * 60 * 24 * 7 * 1000);
  await prisma.refreshToken.create({
    data: {
      tokenHash,
      userId: user.id,
      expiresAt: expires,
    },
  });
  return raw;
};

const generateAccessTokenSystem = (user, system) => {
  let keyENV = "JWT_SECRET_KEY_";
  keyENV += system;

  const id = process.env[keyENV];

  if (id) {
    return jwt.sign(
      {
        ...user,
      },
      process.env[keyENV],
      { expiresIn: "60m" }
    );
  } else {
    return undefined;
  }
};

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString(); // 6 หลัก
};

const sendOTPEmail = async (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "ยืนยันการสมัครสมาชิก - OTP Code",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>ยืนยันการสมัครสมาชิก</h2>
        <p>รหัส OTP ของคุณคือ:</p>
        <div style="font-size: 32px; font-weight: bold; color: #4CAF50; text-align: center; padding: 20px; background: #f5f5f5; border-radius: 8px; margin: 20px 0;">
          ${otp}
        </div>
        <p>รหัสนี้จะหมดอายุใน 5 นาที</p>
        <p>หากคุณไม่ได้สมัครสมาชิก กรุณาเพิกเฉยต่ออีเมลนี้</p>
      </div>
    `,
  };

  return transporter.sendMail(mailOptions);
};

const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_REDIRECT_URI,
});

// ---------------------- register (ไม่ได้ใช้) --------------
export const register = async (req, res, next) => {
  try {
    /* 
      1.keep body
      2.check Email In DB
      3.Encrypt Password -> bcryptjs
      4.Insert into DB
      5.response
    */
    const { email, firstName, lastName, password } = req.body;

    const user = await prisma.user.findFirst({
      where: {
        email: email,
      },
    });

    if (user) {
      return next(createError(409, "อีเมลนี้ถูกใช้งานแล้ว กรุณาใช้อีเมลอื่น"));
    }

    const hashPassword = bcrypt.hashSync(password, 10);
    const result = await prisma.user.create({
      data: {
        email,
        firstName,
        lastName,
        password: hashPassword,
      },
    });

    const { password: _, ...userWithoutPassword } = result;

    res.json({ message: "สมัครสำเร็จ!!!", user: userWithoutPassword });
  } catch (error) {
    next(error);
  }
};

//---------------------- login ----------------------
export const login = async (req, res, next) => {
  // console.log(req.ip);
  // console.log(req.connection?.remoteAddress);
  // console.log(req.socket?.remoteAddress);
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findFirst({
      where: {
        email: email,
      },
    });

    if (user === null) {
      createError(409, "อีเมลหรือรหัสผู้ใช้งานไม่ถูกต้อง");
    }

    const checkPassword = bcrypt.compareSync(password, user.password);

    if (!checkPassword) {
      createError(409, "อีเมลหรือรหัสผู้ใช้งานไม่ถูกต้อง");
    }

    const userToken = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      createAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    const accessToken = generateAccessToken(userToken);
    const refreshToken = await generateRefreshToken(user);

    // ตั้ง Cookie (HttpOnly + Secure)
    res.cookie("jid", refreshToken, {
      httpOnly: true,
      secure: true, // ใช้ https
      sameSite: "Lax", // หรือ "none" ถ้าต้องการ cross-site
      domain: ".family-sivarom.com", // จุดนำหน้า = ใช้ได้ทั้ง domain และ subdomain
      path: "/",
      maxAge: 60 * 60 * 24 * 7 * 1000,
    });

    const { password: _, ...userWithoutPassword } = user;

    res.json({ accessToken, user: userWithoutPassword });
  } catch (error) {
    next(error);
  }
};

export const systemAccess = async (req, res, next) => {
  //TODO: ดัก 401 middleware
  //TODO: Limit Login
  try {
    const { system, user, apiKey } = req.body;

    if (!user || !system || !apiKey) {
      return next(createError(400, "กรุณาใส่ user system และ apiKey"));
    }

    if (apiKey !== process.env.JWT_SECRET_KEY) {
      return next(createError(400, "apiKey ไม่ถูกต้อง"));
    }

    const userToken = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user?.lastName,
      role: user.role,
      createAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
    const accessTokenSystem = generateAccessTokenSystem(userToken, system);
    res.json({ accessTokenSystem });
  } catch (error) {
    next(createError(500, error));
  }
};

// ------------------------ REFRESH ------------------------
export const refreshAccessToken = async (req, res, next) => {
  const refreshToken = req.cookies.jid;
  if (!refreshToken) return res.status(401).json({ error: "No refresh token" });

  const tokenHash = hashRt(refreshToken);
  const dbRt = await prisma.refreshToken.findUnique({
    where: { tokenHash },
    include: {
      user: true, // ดึงข้อมูล user มาด้วย
    },
  });

  if (!dbRt || dbRt.revoked || dbRt.expiresAt < new Date()) {
    return res.status(401).json({ error: "Invalid refresh token" });
  }

  const userToken = {
    id: dbRt.user.id,
    email: dbRt.user.email,
    firstName: dbRt.user.firstName,
    lastName: dbRt.user.lastName,
    role: dbRt.user.role,
    createdAt: dbRt.user.createdAt,
    updatedAt: dbRt.user.updatedAt,
  };

  const accessToken = generateAccessToken(userToken);
  const { password: _, ...userWithoutPassword } = dbRt.user;
  res.json({ accessToken, user: userWithoutPassword });
};

// ------------------------ LOGOUT ------------------------
export const logout = async (req, res) => {
  const refreshToken = req.cookies.jid;
  if (refreshToken) {
    await prisma.refreshToken.updateMany({
      where: { tokenHash: hashRt(refreshToken) },
      data: { revoked: true },
    });
  }

  res.clearCookie("jid"); // ลบ cookie
  res.json({ message: "Logged out" });
};

// ------------------------ ME (ไม่ได้ใช้) ----------------------------
export const authen = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return next(createError(401, "No token provided"));
  const token = authHeader.split(" ")[1];
  try {
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
      if (err) {
        return next(createError(401, "token หมดอายุ"));
      }
      res.json(decoded);
    });
  } catch (err) {
    next(err);
  }
};

//  -------------------- API 1: ส่ง OTP ไปยัง email -----------
export const sendOTP = async (req, res, next) => {
  try {
    const { email, firstName, lastName, password } = req.body;

    // ตรวจสอบว่า email มีในระบบแล้วหรือไม่
    const existingUser = await prisma.user.findFirst({
      where: { email: email },
    });

    if (existingUser) {
      return next(createError(409, "อีเมลนี้ถูกใช้งานแล้ว กรุณาใช้อีเมลอื่น"));
    }

    // สร้าง OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // หมดอายุใน 5 นาที

    // เข้ารหัสรหัสผ่าน
    const hashPassword = bcrypt.hashSync(password, 10);

    // เก็บข้อมูลชั่วคราวในตาราง pending_users หรือใช้ Redis
    await prisma.pendingUser.upsert({
      where: { email: email },
      update: {
        firstName,
        lastName,
        password: hashPassword,
        otp,
        otpExpiry,
        createdAt: new Date(),
      },
      create: {
        email,
        firstName,
        lastName,
        password: hashPassword,
        otp,
        otpExpiry,
      },
    });

    // ส่ง OTP ไปยัง email
    await sendOTPEmail(email, otp);

    res.json({
      message: "ส่งรหัส OTP ไปยังอีเมลแล้ว กรุณาตรวจสอบอีเมลของคุณ",
      email: email,
    });
  } catch (error) {
    console.error("Error sending OTP:", error);
    next(createError(500, "ไม่สามารถส่งรหัส OTP ได้ กรุณาลองใหม่อีกครั้ง"));
  }
};

export const resendOTP = async (req, res, next) => {
  try {
    const { email } = req.body;

    const existingUser = await prisma.pendingUser.findFirst({
      where: { email: email },
    });

    if (!existingUser) {
      return next(createError(409, "อีเมลนี้ยังไม่มีในระบบ"));
    }

    // สร้าง OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // หมดอายุใน 5 นาที
    await prisma.pendingUser.update({
      where: { email },
      data: {
        otp,
        otpExpiry,
      },
    });

    // ส่ง OTP ไปยัง email
    await sendOTPEmail(email, otp);

    res.json({
      message: "ส่งรหัส OTP ไปยังอีเมลแล้ว กรุณาตรวจสอบอีเมลของคุณ",
      email: email,
    });
  } catch (error) {
    console.error("Error sending OTP:", error);
    next(error);
  }
};

// ---------------- API 2: ยืนยัน OTP และสร้างผู้ใช้ ------------------
export const verifyOTPAndRegister = async (req, res, next) => {
  try {
    const { email, otp } = req.body;

    // ตรวจสอบข้อมูลใน pending_users
    const pendingUser = await prisma.pendingUser.findFirst({
      where: { email: email },
    });

    if (!pendingUser) {
      return next(
        createError(404, "ไม่พบข้อมูลการสมัครสมาชิก กรุณาเริ่มต้นใหม่")
      );
    }

    // ตรวจสอบว่า OTP หมดอายุหรือไม่
    if (new Date() > pendingUser.otpExpiry) {
      // await prisma.pendingUser.delete({
      //   where: { email: email },
      // });
      return next(createError(400, "รหัส OTP หมดอายุแล้ว กรุณาขอรหัสใหม่"));
    }

    // ตรวจสอบ OTP
    if (pendingUser.otp !== otp) {
      return next(createError(400, "รหัส OTP ไม่ถูกต้อง กรุณาลองใหม่"));
    }

    // ตรวจสอบว่า email ยังไม่ถูกใช้งาน (double check)
    const existingUser = await prisma.user.findFirst({
      where: { email: email },
    });

    if (existingUser) {
      await prisma.pendingUser.delete({
        where: { email: email },
      });
      return next(createError(409, "อีเมลนี้ถูกใช้งานแล้ว"));
    }

    // สร้างผู้ใช้ใหม่
    const newUser = await prisma.user.create({
      data: {
        email: pendingUser.email,
        firstName: pendingUser.firstName,
        lastName: pendingUser.lastName,
        password: pendingUser.password,
      },
    });

    // ลบข้อมูลใน pending_users
    await prisma.pendingUser.delete({
      where: { email: email },
    });

    const { password: _, ...userWithoutPassword } = newUser;

    res.json({
      message: "สมัครสมาชิกสำเร็จ! บัญชีของคุณได้รับการยืนยันแล้ว",
      user: userWithoutPassword,
    });
  } catch (error) {
    // console.error("Error verifying OTP:", error);
    next(error);
  }
};

// --------------- reset password step 1 ส่ง otp ไปที่ email----------------
// TODO: ทำ reset password
export const resetPassword = async () => {
  try {
    const { email } = req.body;
    const user = await prisma.user.findFirst({
      where: {
        email: email,
      },
    });

    if (user === null) {
      createError(409, "อีเมลหรือรหัสผู้ใช้งานไม่ถูกต้อง");
    }

    // สร้าง OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // หมดอายุใน 5 นาที

    // ส่ง OTP ไปยัง email
    await sendOTPEmail(email, otp);

    res.json({
      message: "ส่งรหัส OTP ไปยังอีเมลแล้ว กรุณาตรวจสอบอีเมลของคุณ",
      email: email,
    });
  } catch (error) {
    next(error);
  }
};

// --------------- reset passowrd step 2 ยืนยัน otp

//----------------- Oauth -------------------------------
export const googleLogin = async (req, res, next) => {
  try {
    const { idToken } = req.body; // รับ ID Token จาก Frontend

    // Verify ID Token กับ Google
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    // ตรวจสอบว่ามี user นี้อยู่แล้วหรือไม่
    let user = await prisma.user.findFirst({
      where: {
        OR: [{ email: email }, { googleId: googleId }],
      },
    });

    // ถ้ายังไม่มี user ให้สร้างใหม่
    if (!user) {
      user = await prisma.user.create({
        data: {
          email,
          firstName: name,
          // TODO: lastName
          googleId,
          profileImage: picture,
          authProvider: "GOOGLE",
          // ไม่ต้องเก็บ password สำหรับ OAuth users
        },
      });
    } else if (!user.googleId) {
      // ถ้ามี email อยู่แล้ว แต่ยังไม่เคย link กับ Google
      user = await prisma.user.update({
        where: { id: user.id },
        data: {
          googleId,
          profileImage: picture || user.profileImage,
          authProvider: user.authProvider || "GOOGLE",
        },
      });
    }

    // สร้าง tokens
    const userToken = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    const accessToken = generateAccessToken(userToken);
    const refreshToken = await generateRefreshToken(user);

    // ตั้ง Cookie
    res.cookie("jid", refreshToken, {
      httpOnly: true,
      secure: true, // ใช้ https
      sameSite: "Lax", // หรือ "none" ถ้าต้องการ cross-site
      domain: ".family-sivarom.com", // จุดนำหน้า = ใช้ได้ทั้ง domain และ subdomain
      path: "/",
      maxAge: 60 * 60 * 24 * 7 * 1000,
    });

    const { password: _, ...userWithoutPassword } = user;

    res.json({
      message: "เข้าสู่ระบบด้วย Google สำเร็จ",
      accessToken,
      user: userWithoutPassword,
    });
  } catch (error) {
    console.error("Google OAuth Error:", error);
    next(createError(401, "การเข้าสู่ระบบด้วย Google ไม่สำเร็จ"));
  }
};

// ---------------- OAuth แบบใหม่ redirect
export const startGoogleLogin = (req, res) => {
  const scopes = ["openid", "email", "profile"];

  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: scopes,
  });

  res.redirect(url);
};

export const googleCallback = async (req, res, next) => {
  try {
    const { code } = req.query;

    // แลก code เป็น tokens
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // ดึงข้อมูล user
    const { data } = await axios.get(
      "https://www.googleapis.com/oauth2/v3/userinfo",
      { headers: { Authorization: `Bearer ${tokens.access_token}` } }
    );

    const { sub: googleId, email, name, picture } = data;

    // หา/สร้าง user
    let user = await prisma.user.findFirst({
      where: { OR: [{ email }, { googleId }] },
    });

    if (!user) {
      user = await prisma.user.create({
        data: {
          email,
          firstName: name,
          googleId,
          profileImage: picture,
          authProvider: "GOOGLE",
        },
      });
    } else if (!user.googleId) {
      user = await prisma.user.update({
        where: { id: user.id },
        data: {
          googleId,
          profileImage: picture || user.profileImage,
          authProvider: "GOOGLE",
        },
      });
    }

    // สร้าง tokens ของระบบคุณเอง
    const userToken = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    const accessToken = generateAccessToken(userToken);
    const refreshToken = await generateRefreshToken(user);

    // ส่ง cookie refresh token
    res.cookie("jid", refreshToken, {
      httpOnly: true,
      secure: true, // ใช้ https
      sameSite: "Lax", // หรือ "none" ถ้าต้องการ cross-site
      domain: ".family-sivarom.com", // จุดนำหน้า = ใช้ได้ทั้ง domain และ subdomain
      path: "/",
      maxAge: 60 * 60 * 24 * 7 * 1000,
    });

    // Redirect กลับไปหน้า dashboard frontend
    res.redirect(
      "https://homepass-web.family-sivarom.com/dashboard?token=" + accessToken
    );
  } catch (err) {
    console.error("Google Callback Error:", err);
    next(createError(401, "Google login ล้มเหลว"));
  }
};

// ---------------- LINE Login (OAuth 2.1 / OpenID Connect) ----------------
// ต้องตรงกับ Callback URL ใน LINE Developers Console และอยู่ host เดียวกับ /auth/line (ไม่งั้น cookie state จะหาย)
const LINE_REDIRECT_URI =
  process.env.LINE_REDIRECT_URI ||
  "https://www.family-sivarom.com/auth/line/callback";
const FRONTEND_URL =
  process.env.FRONTEND_URL || "https://homepass-web.family-sivarom.com";

const LINE_STATE_COOKIE = "line_oauth";
const lineStateCookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "Lax", // ห้ามใช้ Strict ไม่งั้น cookie จะไม่ถูกส่งมาตอน LINE redirect กลับ
  path: "/auth/line",
};

// ส่งผู้ใช้กลับหน้าเว็บ พร้อม error code (ถ้ามี) — ไม่ส่ง token ทาง URL
const redirectLineResult = (res, error) => {
  const url = new URL("/auth/line/callback", FRONTEND_URL);
  if (error) url.searchParams.set("error", error);
  res.redirect(url.toString());
};

export const startLineLogin = (req, res) => {
  if (!process.env.LINE_CHANNEL_ID || !process.env.LINE_CHANNEL_SECRET) {
    console.error("LINE Login Error: ยังไม่ได้ตั้งค่า LINE_CHANNEL_ID / LINE_CHANNEL_SECRET");
    return redirectLineResult(res, "failed");
  }

  // state กัน CSRF, nonce กัน replay ของ id_token
  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");

  res.cookie(LINE_STATE_COOKIE, `${state}.${nonce}`, {
    ...lineStateCookieOptions,
    maxAge: 10 * 60 * 1000, // 10 นาที
  });

  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.LINE_CHANNEL_ID,
    redirect_uri: LINE_REDIRECT_URI,
    state,
    scope: "profile openid email",
    nonce,
  });

  res.redirect(`https://access.line.me/oauth2/v2.1/authorize?${params}`);
};

export const lineCallback = async (req, res) => {
  const { code, state, error } = req.query;
  const [savedState, nonce] = (req.cookies[LINE_STATE_COOKIE] || "").split(".");
  res.clearCookie(LINE_STATE_COOKIE, lineStateCookieOptions);

  // ผู้ใช้กดยกเลิกที่หน้า LINE
  if (error) return redirectLineResult(res, "cancelled");

  if (!code || !savedState || state !== savedState) {
    console.error("LINE Callback Error: state ไม่ตรงหรือหมดอายุ");
    return redirectLineResult(res, "failed");
  }

  try {
    // แลก code เป็น tokens
    const { data: tokens } = await axios.post(
      "https://api.line.me/oauth2/v2.1/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: LINE_REDIRECT_URI,
        client_id: process.env.LINE_CHANNEL_ID,
        client_secret: process.env.LINE_CHANNEL_SECRET,
      })
    );

    // ให้ LINE ตรวจ id_token (ลายเซ็น, วันหมดอายุ, audience, nonce) แล้วคืนข้อมูล user
    const { data: profile } = await axios.post(
      "https://api.line.me/oauth2/v2.1/verify",
      new URLSearchParams({
        id_token: tokens.id_token,
        client_id: process.env.LINE_CHANNEL_ID,
        nonce,
      })
    );

    const { sub: lineId, email, name, picture } = profile;

    // หา/สร้าง user
    let user = await prisma.user.findUnique({ where: { lineId } });

    if (!user) {
      // ระบบอื่น (MA, APP, ...) ใช้ email ระบุตัว user จึงต้องมี email เสมอ
      if (!email) return redirectLineResult(res, "no_email");

      user = await prisma.user.findUnique({ where: { email } });

      if (!user) {
        user = await prisma.user.create({
          data: {
            email,
            firstName: name,
            lineId,
            profileImage: picture,
            authProvider: "LINE",
          },
        });
      } else if (!user.lineId) {
        // มี email นี้อยู่แล้ว (สมัครด้วย email/Google) → ผูกกับ LINE
        user = await prisma.user.update({
          where: { id: user.id },
          data: {
            lineId,
            profileImage: user.profileImage || picture,
            authProvider: user.authProvider || "LINE",
          },
        });
      }
    }

    const refreshToken = await generateRefreshToken(user);

    // ส่ง cookie refresh token
    res.cookie("jid", refreshToken, {
      httpOnly: true,
      secure: true, // ใช้ https
      sameSite: "Lax", // หรือ "none" ถ้าต้องการ cross-site
      domain: ".family-sivarom.com", // จุดนำหน้า = ใช้ได้ทั้ง domain และ subdomain
      path: "/",
      maxAge: 60 * 60 * 24 * 7 * 1000,
    });

    await createUserLog(user.id, "LOGIN", "User logged in with LINE", req, {
      provider: "LINE",
    });

    // หน้าเว็บจะเรียก /auth/refreshToken (ใช้ cookie jid) เพื่อรับ accessToken + user
    redirectLineResult(res);
  } catch (err) {
    console.error("LINE Callback Error:", err.response?.data || err);
    redirectLineResult(res, "failed");
  }
};

export const dog = (req, res, next) => {
  try {
    res.json({ message: "dog" });
  } catch (error) {
    console.error("Google OAuth Error:", error);
    next(createError(401, "การเข้าสู่ระบบด้วย Google ไม่สำเร็จ"));
  }
};
