import { Router } from "express";
import { loginUser, registerUser, logoutUser, refreshAccessToken, changeCurrentPassword, getCurrentUser, updateAccountDetails, updateUserAvatar} from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router()

router.route("/register").post(
  //injecting middleware - multer
  upload.fields([
    // to accept  files
    {
      name:"avatar",   //same should be name in frontend
      maxCount: 1
    }
  ]),
  //then running method
  registerUser
)

router.route("/login").post(loginUser)

//secured routes --> when user is loged in
router.route("/logout").post( verifyJWT, logoutUser )
router.route("/refresh-token").post(refreshAccessToken)   //no need of middleware in our logic
router.route("/change-password").post(verifyJWT, changeCurrentPassword)
router.route("/current-user").get(verifyJWT, getCurrentUser)
router.route("/update-account").patch(verifyJWT, updateAccountDetails)    //patch as updation

router.route("/avatar").patch(verifyJWT, upload.single("avatar"), updateUserAvatar)   //verify user first then upload


export default router