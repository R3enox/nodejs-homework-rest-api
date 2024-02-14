const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
const path = require("node:path");
const fs = require("node:fs/promises");
const Jimp = require("jimp");

const { SECRET_KEY, BASE_URL } = process.env;

const { User } = require("../models/user");

const { HttpError, ctrlWrapper, sendEmail } = require("../helpers");
const { nanoid } = require("nanoid");

const avatarDir = path.join(__dirname, "../", "public", "avatars");

const signUp = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (user) {
    throw HttpError(409, "Email in use");
  }
  const hashPassword = await bcrypt.hash(password, 10);
  const avatarURL = gravatar.url(email);
  const verificationToken = nanoid();

  const newUser = await User.create({
    ...req.body,
    password: hashPassword,
    avatarURL,
    verificationToken,
  });

  const verifyEmail = {
    to: email,
    from: "nikr3enox@gmail.com",
    subject: "Verify your email",
    html: `To confirm your registration please click on the <a href="${BASE_URL}/api/users/verify/${verificationToken}">link</a>`,
    text: `To confirm your registration please open the link ${BASE_URL}/api/auth/verify/${verificationToken}`,
  };

  await sendEmail(verifyEmail);

  res.status(201).json({
    email: newUser.email,
    name: newUser.name,
  });
};

const verifyEmail = async (req, res) => {
  const { verificationToken } = req.params;
  const user = await User.findOne({ verificationToken });

  if (!user) throw HttpError(404, "User not found");
  await User.findByIdAndUpdate(user._id, {
    verify: true,
    verificationToken: null,
  });
  res.json({ message: "Verification successful" });
};

const resendVerifyEmail = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) throw HttpError(400, "Email not found");

  if (user.verify) throw HttpError(400, "Verification has already been passed");

  const verifyEmail = {
    to: email,
    from: "nikr3enox@gmail.com",
    subject: "Verify your email",
    html: `To confirm your registration please click on the <a target=_blank href="${BASE_URL}/api/users/verify/${user.verificationToken}">link</a>`,
    text: `To confirm your registration please open the link ${BASE_URL}/api/auth/verify/${user.verificationToken}`,
  };

  await sendEmail(verifyEmail);

  res.json({ message: "Verification email sent" });
};

const singIn = async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    throw HttpError(401, "Email or password is wrong");
  }

  if (!user.verify) throw HttpError(401, "Email not verified");

  const passwordCompare = await bcrypt.compare(password, user.password);
  if (!passwordCompare) {
    throw HttpError(401, "Email or password is wrong");
  }

  const paylod = {
    id: user._id,
  };

  const token = jwt.sign(paylod, SECRET_KEY, { expiresIn: "1h" });
  const subscription = user.subscription;
  await User.findByIdAndUpdate(user._id, { token });
  res.json({ token, user: { email, subscription } });
};

const getCurrent = (req, res) => {
  const { email, subscription } = req.user;
  res.json({ email, subscription });
};

const signOut = async (req, res) => {
  const { _id } = req.user;
  await User.findByIdAndUpdate(_id, { token: null });

  res.json();
};

const updateSubscriptionUser = async (req, res) => {
  const { _id } = req.user;
  const result = await User.findByIdAndUpdate(_id, req.body, {
    new: true,
  }).select("-createdAt -updatedAt");

  if (!result) throw HttpError(404, "Not found");
  res.json(result);
};

const updateUserAvatar = async (req, res) => {
  const { _id } = req.user;
  const { path: tempUpload, originalname } = req.file;
  const filename = `${_id}_${originalname}`;
  const resultUpload = path.join(avatarDir, filename);

  const img = await Jimp.read(tempUpload);
  await img.resize(250, 250).writeAsync(tempUpload);

  await fs.rename(tempUpload, resultUpload);
  const avatarURL = path.join("avatars", filename);
  await User.findByIdAndUpdate(_id, { avatarURL });

  res.json({ avatarURL });
};

module.exports = {
  signUp: ctrlWrapper(signUp),
  singIn: ctrlWrapper(singIn),
  getCurrent: ctrlWrapper(getCurrent),
  signOut: ctrlWrapper(signOut),
  updateSubscriptionUser: ctrlWrapper(updateSubscriptionUser),
  updateUserAvatar: ctrlWrapper(updateUserAvatar),
  verifyEmail: ctrlWrapper(verifyEmail),
  resendVerifyEmail: ctrlWrapper(resendVerifyEmail),
};
