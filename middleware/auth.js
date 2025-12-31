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
  // Prefer cookie token, fallback to Authorization header
  const cookieToken = req.cookies?.token;
  const authHeader = req.headers["authorization"];
  const headerToken = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN
  const token = cookieToken || headerToken;

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
      console.log("User not found")
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    // Cleanup expired tokens proactively
    await user.removeExpiredRefreshTokens();

    // Check if refresh token exists in user's tokens
    const storedToken = user.refreshTokens.find(
      (rt) => rt.token === refreshToken
    );
    if (!storedToken) {
      // Security: If token not found, invalidate all refresh tokens
      user.refreshTokens = [];
      await user.save();
      console.log("Stored token not found")
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    // Check if refresh token is expired
    if (storedToken.expiresAt < new Date()) {
      // Remove expired token and reject
      await user.removeRefreshToken(refreshToken);
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
      ...securityConfig.refreshTokenDuration,
    });

    res.cookie("token", newAccessToken, {
      ...securityConfig.cookie,
      ...securityConfig.accessTokenDuration,
    });

    res.status(200).json({ message: "Tokens refreshed" });
  } catch (error) {
    console.log("Error: ", error);
    return res.status(403).json({ message: "Invalid refresh token" });
  }
};
