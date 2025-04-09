import prisma from "../config/prisma";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { sendOTPEmail } from "../utils/mailer";
import { generateOTP } from "../utils/otp";
import { OTP_EXPIRES_IN_MINUTES, RESET_TOKEN_EXPIRES_IN_MINUTES, JWT_SECRET } from "../config/constants";

const OTP_EXPIRES_IN = OTP_EXPIRES_IN_MINUTES * 60 * 1000;
const RESET_TOKEN_EXPIRES_IN = `${RESET_TOKEN_EXPIRES_IN_MINUTES}m`as const;

// Đăng ký
export const register = async (name: string, email: string, password: string) => {
  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) throw new Error("Email already exists");

  const hashedPassword = await bcrypt.hash(password, 10);
  const otp = generateOTP();
  const otpExpiresAt = new Date(Date.now() + OTP_EXPIRES_IN);

  await prisma.user.create({
    data: { name, email, password: hashedPassword, otp, otpExpiresAt },
  });

  await sendOTPEmail(email, otp);
  return { message: "User registered. Please check email for OTP." };
};

// Xác thực OTP
export const verifyOTP = async (email: string, otp: string) => {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error("User not found");
  if (user.isVerified) throw new Error("User already verified");
  if (user.otp !== otp) throw new Error("Invalid OTP");
  if (!user.otpExpiresAt || user.otpExpiresAt < new Date()) throw new Error("OTP has expired");

  await prisma.user.update({
    where: { email },
    data: { isVerified: true, otp: null, otpExpiresAt: null },
  });

  return { message: "Email verified successfully" };
};

// Gửi lại OTP
export const resendOTP = async (email: string) => {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error("User not found");
  if (user.isVerified) throw new Error("User already verified");

  const otp = generateOTP();
  const otpExpiresAt = new Date(Date.now() + OTP_EXPIRES_IN);

  await prisma.user.update({ where: { email }, data: { otp, otpExpiresAt } });
  await sendOTPEmail(email, otp);

  return { message: "New OTP sent to your email" };
};

// Đăng nhập
export const login = async (email: string, password: string) => {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error("User not found");
  if (!user.isVerified) throw new Error("Email not verified");

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) throw new Error("Invalid credentials");

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: "7d",
  });

  return { message: "Login successful", token };
};

// Gửi OTP quên mật khẩu
export const forgotPassword = async (email: string) => {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error("User not found");

  const otp = generateOTP();
  const otpExpiresAt = new Date(Date.now() + OTP_EXPIRES_IN);

  await prisma.user.update({ where: { email }, data: { otp, otpExpiresAt } });
  await sendOTPEmail(email, otp);

  return { message: "OTP sent to your email" };
};

// Xác thực OTP để reset password 
export const verifyResetOTP = async (email: string, otp: string) => {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error("User not found");
  if (user.otp !== otp) throw new Error("Invalid OTP");
  if (!user.otpExpiresAt || user.otpExpiresAt < new Date()) throw new Error("OTP has expired");

  const resetToken = jwt.sign({ email }, JWT_SECRET, {
    expiresIn: RESET_TOKEN_EXPIRES_IN,
  });
 
  

  return { message: "OTP verified", resetToken };
};

// Đặt lại mật khẩu với reset token
export const resetPasswordWithToken = async (resetToken: string, newPassword: string) => {
  try {
    const payload = jwt.verify(resetToken, JWT_SECRET) as { email: string };
    const user = await prisma.user.findUnique({ where: { email: payload.email } });
    if (!user) throw new Error("User not found");

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { email: payload.email },
      data: { password: hashedPassword, otp: null, otpExpiresAt: null },
    });

    return { message: "Password reset successful" };
  } catch (err) {
    throw new Error("Invalid or expired reset token");
  }
};
