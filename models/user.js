import { Schema, model } from "mongoose";

import { addError, updateError } from "../helpers/hooks-errors.js";

import { emailRegexp } from "../constants/user-constants.js";

const userSchema = new Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    match: emailRegexp,
    required: [true, 'Email is required'],
    unique: true,
  },
  password: {
    type: String,
    minlength: 6,
    required: [true, 'Set password for user'],
  },
  avatarURL: {
    type: String,
    required: true,
  },
  token: {
    type: String,
  },
  verify: {
    type: Boolean,
    default: false,
  },
  verificationCode: {
    type: String,
  }
}, { versionKey: false, timestamps: true });

userSchema.pre("findOneAndUpdate", updateError);

userSchema.post("save", addError);

userSchema.post("findOneAndUpdate", addError);

const User = model("user", userSchema);

export default User;