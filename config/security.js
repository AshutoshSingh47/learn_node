export const securityConfig = {
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "1d",
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
    expiresIn: "24h",
  },
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    path: "/",
    sameSite: "lax",
  },
  accessTokenDuration: {
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  },
  refreshTokenDuration: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  },
  bcrypt: {
    saltRounds: 12,
  },
};
