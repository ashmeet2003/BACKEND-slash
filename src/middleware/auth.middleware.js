// it verifies user on basis of token that he is logged in, and adds an object in req that can access info. in jwt
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";

//strategy -> add an object in req on verification
export const verifyJWT = asyncHandler(async(req, res, next) => {
  try {
    //token access by accessing the cookies
    //may mobile browser so no access to cookies, custom header used to access cookie
    const token = req.cookies.accessToken //|| req.header("Authorization")?.replace("Bearer ", "")
    
    if(!token){
      throw new ApiError(401, "Unauthorized Access")
    }
    
    //decoding info provided to jwt --> now have access to data stored in it
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)  
    //taking out user using decoded info
    const user = await User.findById(decodedToken?._id).select("-password -refreshToken")
  
    if(!user){
      throw new ApiError(401, "Invalid Access Token")
    }
  
    //adding object in the req
    req.user = user;
    next()
  } catch (error) {
    throw new ApiError(401, error?.message || "invalid Acess Token")
  }
})