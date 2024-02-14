const express = require("express");
const authController = require("../../controllers/authController");
const {
  validateBody,
  authenticate,
  isEmptyBody,
  upload,
} = require("../../middlewares");

const { schemas } = require("../../models/user");
const router = express.Router();

router.post(
  "/register",
  isEmptyBody,
  validateBody(schemas.signUpSchema),
  authController.signUp
);

router.get("/verify/:verificationToken", authController.verifyEmail);

router.post(
  "/verify",
  validateBody(schemas.emailSchema),
  authController.resendVerifyEmail
);

router.post(
  "/login",
  isEmptyBody,
  validateBody(schemas.signInSchema),
  authController.singIn
);

router.get("/current", authenticate, authController.getCurrent);

router.post("/logout", authenticate, authController.signOut);

router.patch(
  "/",
  authenticate,
  isEmptyBody,
  validateBody(schemas.updateSubscriptionSchema),
  authController.updateSubscriptionUser
);

router.patch(
  "/avatars",
  authenticate,
  upload.single("avatar"),
  authController.updateUserAvatar
);

module.exports = router;
