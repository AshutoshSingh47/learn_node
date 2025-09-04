import { connect, Schema, model } from "mongoose";

connect(process.env.MONGODB_URI);

const userSchema = new Schema({
  username: String,
  name: String,
  email: String,
  age: String,
  password: String,
  profilepic: {
    type: String,
    default: "default.jpg",
  },
  posts: [{ type: Schema.Types.ObjectId, ref: "post" }],
  refreshTokens: [
    {
      token: String,
      expiresAt: Date,
      createdAt: {
        type: Date,
        default: Date.now,
      },
    },
  ],
});

userSchema.methods.addRefreshToken = function (token, expiresAt) {
  this.refreshTokens.push({
    token,
    expiresAt,
  });
  return this.save();
};

userSchema.methods.removeRefreshToken = function (token) {
  this.refreshTokens = this.refreshTokens.filter((rt) => rt.token !== token);
  return this.save();
};

userSchema.methods.removeExpiredRefreshTokens = function () {
  const now = new Date();
  this.refreshTokens = this.refreshTokens.filter((rt) => rt.expiresAt > now);
  return this.save();
};

const userModel = model("user", userSchema);

export default userModel;
