import prisma from "../config/prisma.js";

// ฟังก์ชันสำหรับสร้าง log
export const createUserLog = async (
  userId,
  action,
  description,
  req = null,
  metadata = null
) => {
  try {
    const logData = {
      userId,
      action,
      description,
      metadata,
    };

    // เพิ่มข้อมูล IP Address และ User Agent ถ้ามี request object
    if (req) {
      logData.ipAddress =
        req.ip ||
        req.connection.remoteAddress ||
        req.headers["x-forwarded-for"];
      logData.userAgent = req.headers["user-agent"];
    }

    await prisma.userLog.create({
      data: logData,
    });

    console.log(`User log created: ${action} for user ${userId}`);
  } catch (error) {
    console.error("Error creating user log:", error);
    // ไม่ throw error เพื่อไม่ให้กระทบกับ main function
  }
};
