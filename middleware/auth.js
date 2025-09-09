import {
  verifyAccessToken,
  verifyRefreshToken,
  generateAccessToken,
  generateRefreshToken,
} from "../config/tokenService.js";
import userModel from "../models/user.js";
import { securityConfig } from "../config/security.js";

// Middleware to check access token
export const authenticateAccessToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  try {
    const decoded = verifyAccessToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid or expired access token" });
  }
};

// Middleware to refresh access token
export const refreshAccessToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token required" });
  }

  try {
    // Verify refresh token
    const decoded = verifyRefreshToken(refreshToken);

    // Find user and check if refresh token exists
    const user = await userModel.findById(decoded.userid);
    if (!user) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    // Check if refresh token exists in user's tokens
    const storedToken = user.refreshTokens.find(
      (rt) => rt.token === refreshToken
    );
    if (!storedToken) {
      // Security: If token not found, invalidate all refresh tokens
      user.refreshTokens = [];
      await user.save();
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    // Check if refresh token is expired
    if (storedToken.expiresAt < new Date()) {
      // Remove expired token
      return res.status(403).json({ message: "Expired refresh token" });
    }

    // Implement refresh token rotation
    // Remove the used refresh token
    await user.removeRefreshToken(refreshToken);

    // Generate new tokens
    const newAccessToken = generateAccessToken({
      email: decoded.email,
      userid: decoded.userid,
    });

    const newRefreshToken = generateRefreshToken({
      email: decoded.email,
      userid: decoded.userid,
    });

    // Add new refresh token to user
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days from now
    await user.addRefreshToken(newRefreshToken, expiresAt);

    // Send new tokens
    res.cookie("refreshToken", newRefreshToken, {
      ...securityConfig.cookie,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({
      accessToken: newAccessToken,
      expiresIn: securityConfig.jwt.accessExpiresIn,
    });
  } catch (error) {
    console.log("Error: ", error);
    return res.status(403).json({ message: "Invalid refresh token" });
  }
};
