import { createUserLog } from "../utils/logUser.js";
import prisma from "../config/prisma.js";
import createError from "../utils/createError.js";

export const preLogUserAction = (
  action,
  getDescription,
  getMetadata = null
) => {
  return async (req, res, next) => {
    try {
      let userId;
      userId = req.user?.id || req.userId;

      if (!userId && req.body.email) {
        const user = await prisma.user.findFirst({
          where: {
            email: req.body.email,
          },
        });

        if (user === null) {
          createError(409, "อีเมลหรือรหัสผู้ใช้งานไม่ถูกต้อง");
        }

        userId = user.id;
      }

      if (userId || req.body.email) {
        // สร้าง description แบบ dynamic
        const description =
          typeof getDescription === "function"
            ? getDescription(req, res)
            : getDescription;

        // สร้าง metadata แบบ dynamic (ถ้ามี)
        const metadata = getMetadata
          ? typeof getMetadata === "function"
            ? getMetadata(req, res)
            : getMetadata
          : null;

        console.log(26, {
          userId,
          action,
          description,
        });

        // Log ก่อนเข้า endpoint
        await createUserLog(userId, action, description, req, metadata);
      }

      next(); // ส่งต่อไป controller
    } catch (error) {
      console.error("Error in preLogUserAction middleware:", error);
      next(error); // ให้ request ดำเนินต่อไปแม้ว่า log จะ error
    }
  };
};

export const preLogLogin = preLogUserAction(
  "LOGIN",
  (req) => `User attempting to login with email: ${req.body.email}`,
  (req) => ({ email: req.body.email, timestamp: new Date() })
);

export const preLogSearch = preLogUserAction(
  "SEARCH",
  (req) => `User searching for: ${req.query.q || req.body.query || "unknown"}`,
  (req) => ({
    query: req.query.q || req.body.query,
    filters: req.query.filters,
  })
);

export const preLogCustomerAccess = preLogUserAction(
  "CUSTOMER",
  (req) => {
    const method = req.method;
    switch (method) {
      case "GET":
        return req.params.id
          ? `Viewing customer ${req.params.id}`
          : "Accessing customer list";
      case "POST":
        return "Creating new customer";
      case "PUT":
      case "PATCH":
        return `Updating customer ${req.params.id}`;
      case "DELETE":
        return `Deleting customer ${req.params.id}`;
      default:
        return `Customer ${method} operation`;
    }
  },
  (req) => ({
    customerId: req.params.id,
    method: req.method,
  })
);
