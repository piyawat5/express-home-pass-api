import { object, string } from "yup";
import createError from "../utils/createError.js";
//ตรงส่วนนี้สามารถ copy ไปใช้ฝั่งหน้าบ้านได้ด้วย
export const registerSchema = object({
  email: string()
    .email("กรุณากรอกเป็นรูปแบบ Email")
    .required("กรุณากรอก Email"),
  firstName: string()
    .min(3, "กรุณากรอกชื่อ 3 ตัวอักษร")
    .required("กรุณากรอกชื่อ"),
  lastName: string()
    .min(3, "กรุณากรอกชื่อ 3 ตัวอักษร")
    .required("กรุณากรอกชื่อ"),
  password: string()
    .min(6, "กรุณากรอกรหัสผ่าน อย่างน้อย 6 ตัวอักษร")
    .required("กรุณากรอกรหัสผ่าน"),
});

export const loginSchema = object({
  email: string()
    .email("กรุณากรอกเป็นรูปแบบ Email")
    .required("กรุณากรอก Email"),
  password: string()
    .min(6, "กรุณากรอกรหัสผ่าน อย่างน้อย 6 ตัวอักษร")
    .required("กรุณากรอกรหัสผ่าน"),
});

export const validate = (schema) => async (req, res, next) => {
  try {
    //abortEarly มีไว้สำหรับเช็คให้หมดทุกตัว ไม่ใช่เจอ error แล้วหยุด
    await schema.validate(req.body, { abortEarly: true });
    next();
  } catch (error) {
    createError(400, error.errors.join(","));
    // const errTxt = error.errors.join(",");
    // const err = new Error(errTxt);
    // err.code = 400;
    // next(error);
  }
};
