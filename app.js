import "dotenv/config";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import express from "express";
import path from "path";
import jwt from "jsonwebtoken";
import postModel from "./models/post.js";
import userModel from "./models/user.js";
import upload from "./config/multerconfig.js";
import { fileURLToPath } from "url";
import { securityConfig } from "./config/security.js";
import {
  generateAccessToken,
  generateRefreshToken,
} from "./config/tokenService.js";
import {
  authenticateAccessToken,
  refreshAccessToken,
} from "./middleware/auth.js";

const app = express();
const PORT = process.env.PORT || 8080;

const __fileName = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__fileName);

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const cookieOptionShort = {
  httpOnly: true,
  maxAge: 10 * 1000,
  path: "/",
};

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/profile/upload", (req, res) => {
  res.render("profileupload");
});

app.post("/upload", isLoggedIn, upload.single("image"), async (req, res) => {
  const { email } = req.user;
  const user = await userModel.findOne({ email });

  user.profilepic = req.file.filename;
  await user.save();
  res.redirect("/profile");
});

app.get("/profile", isLoggedIn, async (req, res) => {
  const { email } = req.user;
  const user = await userModel.findOne({ email }).populate("posts");
  res.render("profile", { user });
});

app.get("/test", (req, res) => {
  res.render("test");
});

app.get("/like/:id", isLoggedIn, async (req, res) => {
  const postId = req.params.id;

  const post = await postModel.findOne({ _id: postId }).populate("user");

  if (post.likes.indexOf(req.user.userid) === -1) {
    post.likes.push(req.user.userid);
  } else {
    post.likes.splice(post.likes.indexOf(req.user.userid), 1);
  }

  await post.save();
  res.redirect("/profile");
});

app.get("/edit/:id", isLoggedIn, async (req, res) => {
  const postId = req.params.id;
  const post = await postModel.findOne({ _id: postId });

  res.render("edit", { post });
});

app.post("/update/:id", isLoggedIn, async (req, res) => {
  const postId = req.params.id;
  const { content } = req.body;
  const post = await postModel.findOneAndUpdate({ _id: postId }, { content });
  res.redirect("/profile");
});

app.post("/register", async (req, res) => {
  const { email, password, username, name, age } = req.body;

  const user = await userModel.findOne({ email });
  if (user) return res.status(500).send("User already registered");

  bcrypt.genSalt(securityConfig.bcrypt.saltRounds, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      const newUser = await userModel.create({
        username,
        email,
        age,
        name,
        password: hash,
      });
      const accessToken = generateAccessToken({
        email: email,
        userid: newUser._id,
      });
      const refreshToken = generateRefreshToken({
        email: email,
        userid: newUser._id,
      });
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7); // 7 days from now
      await newUser.addRefreshToken(refreshToken, expiresAt);
      res.cookie("refreshToken", refreshToken, {
        ...securityConfig.cookie,
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.cookie("token", accessToken, cookieOptionShort);
      res.send("Registered");
    });
  });
});

app.post("/post", isLoggedIn, async (req, res) => {
  const { email } = req.user;
  const { content } = req.body;
  const user = await userModel.findOne({ email });

  const post = await postModel.create({
    user: user._id,
    content,
  });

  user.posts.push(post._id);
  await user.save();
  res.redirect("/profile");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await userModel.findOne({ email });
  if (!user) return res.status(500).send("Something went wrong");

  bcrypt.compare(password, user.password, async (err, result) => {
    if (result) {
      const accessToken = generateAccessToken({
        email: email,
        userid: user._id,
      });
      const refreshToken = generateRefreshToken({
        email: email,
        userid: user._id,
      });

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7); // 7 days from now
      await user.addRefreshToken(refreshToken, expiresAt);

      res.cookie("refreshToken", refreshToken, {
        ...securityConfig.cookie,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });
      res.cookie("token", accessToken, cookieOptionShort);
      return res.status(200).send("You can login");
    } else res.redirect("/login");
  });
});

app.post("/refresh-token", refreshAccessToken);

app.get("/logout", async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      // Remove refresh token from user's record
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      const user = await userModel.findById(decoded.userid);
      if (user) {
        await user.removeRefreshToken(refreshToken);
      }
    }

    // Clear cookies
    res.clearCookie("token");
    res.clearCookie("refreshToken");
    res.redirect("/login");
  } catch (error) {
    res.clearCookie("token");
    res.clearCookie("refreshToken");
    res.redirect("/login");
  }
});

app.get("/api/profile", authenticateAccessToken, async (req, res) => {
  try {
    const user = await userModel.findById(req.user.userid).select("-password");
    res.json({ user });
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch profile" });
  }
});

function isLoggedIn(req, res, next) {
  const accessToken = req.cookies.token;

  if (!accessToken) {
    return res.redirect("/login");
  }

  try {
    const decoded = jwt.verify(
      accessToken,
      process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET
    );
    req.user = decoded;
    next();
  } catch (error) {
    // If access token is expired, check for refresh token
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.redirect("/login");
    }

    // In a real implementation, you would redirect to a refresh endpoint
    // For simplicity in this example, we'll redirect to login
    return res.redirect("/login");
  }
}

app.listen(PORT, () => console.log("Server running successfully"));
