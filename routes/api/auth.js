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

router.post(
  "/login",
  isEmptyBody,
  validateBody(schemas.signInSchema),
  authController.singIn
);

router.get("/current", authenticate, authController.getCurrent);

router.post("/logout", authenticate, authController.signOut);

router.patch(
  "/avatars",
  authenticate,
  upload.single("avatar"),
  authController.updateUserAvatar
);

module.exports = router;
