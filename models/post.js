import { Schema, model } from "mongoose";

const postSchema = new Schema({
  user: [
    {
      type: Schema.Types.ObjectId,
      ref: "user",
    },
  ],
  content: String,
  date: {
    type: Date,
    default: Date.now,
  },
  likes: [{ type: Schema.Types.ObjectId, ref: "user" }],
});

const postModel = model("post", postSchema);

export default postModel;
