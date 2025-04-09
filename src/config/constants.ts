
export const OTP_EXPIRES_IN_MINUTES = parseInt(process.env.OTP_EXPIRES_IN_MINUTES || "5");
export const RESET_TOKEN_EXPIRES_IN_MINUTES = parseInt(process.env.RESET_TOKEN_EXPIRES_IN_MINUTES || "10");
export const JWT_SECRET = process.env.JWT_SECRET || "default_secret";
