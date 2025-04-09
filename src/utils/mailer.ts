import nodemailer from 'nodemailer';
import { mailConfig } from '../config/mail';

const transporter = nodemailer.createTransport(mailConfig);

export const sendOTPEmail = async (to: string, otp: string) => {
  const mailOptions = {
    from: `"Orebi App" <${mailConfig.auth.user}>`,
    to,
    subject: 'Your OTP Code',
    html: `<p>Your OTP code is: <b>${otp}</b></p>`
  };

  await transporter.sendMail(mailOptions);
};
