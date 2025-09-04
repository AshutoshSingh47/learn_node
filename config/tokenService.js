import jwt from "jsonwebtoken";
import { securityConfig } from "./security.js";

// Generate access token
export const generateAccessToken = (payload) => {
  return jwt.sign(payload, securityConfig.jwt.accessSecret, {
    expiresIn: securityConfig.jwt.accessExpiresIn,
  });
};

// Generate refresh token
export const generateRefreshToken = (payload) => {
  return jwt.sign(payload, securityConfig.jwt.refreshSecret, {
    expiresIn: securityConfig.jwt.refreshExpiresIn,
  });
};

// Verify access token
export const verifyAccessToken = (token) => {
  return jwt.verify(token, securityConfig.jwt.accessSecret);
};

// Verify refresh token
export const verifyRefreshToken = (token) => {
  return jwt.verify(token, securityConfig.jwt.refreshSecret);
};
