import { Router } from "express";
import { registerUser, login, logout, refreshAccessToken, changePassword,  getUserDetails, updateAccountDetails, UpdateAvatar, UpdateCoverImage, getchannelProfile, getWatchHistory } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js"
import { verifyJwt } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(
    upload.fields(
        [
            {
                name: "avatar",
                maxCount: 1
            },
            {
                name: "coverImage",
                maxCount: 1
            }
        ]
    ),
    registerUser)

router.route("/login").post(login)

router.route("/logout").post(verifyJwt , logout)

router.route("/refreshToken").post(refreshAccessToken)

router.route("/change-password").post(verifyJwt, changePassword)

router.route("/get-user-details").get(verifyJwt, getUserDetails)

router.route("/update-details").patch(verifyJwt, updateAccountDetails)

router.route("/update-avatar").patch(verifyJwt, upload.single("avatar"), UpdateAvatar)

router.route("/update-cover-image").patch(verifyJwt, upload.single("coverImage"), UpdateCoverImage) 

router.route("/c/:userName").get(verifyJwt, getchannelProfile) 

router.route("/history").get(verifyJwt, getWatchHistory)


export default router