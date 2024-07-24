import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"
import mongoose from "mongoose";

//method to generate tokens
const generateAccessAndRefreshTokens = async(userId) => {
  try{
    const user = await User.findById(userId)
    const accessToken = user.generateAccessToken()
    const refreshToken = user.generateRefreshToken()

    user.refreshToken = refreshToken
    await user.save({validateBeforeSave : false})

    return {accessToken, refreshToken}

  } catch(error){
      throw new ApiError(500, "something went wrong while generating token" )
  }
}

const registerUser = asyncHandler( async (req, res) => {
  //steps - get user detail
  //validation
  //check if user already exist
  //check for images, check for avatar
  //upload them to cloudinary
  //create user object - create entry in db
  //remove password and refresh token field from respomse
  //check for user creation
  //return response

  //get user detail
  const {fullName, email, username, password} = req.body
  console.log("email : ", email);

  /*if(fullName===""){
    //using model designed in utils
    throw new ApiError(400, "full name is requires")
  }*/
  //handling all if-else at once instead of above
  if(
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ){
    //using error model designed
    throw new ApiError(400, "All Fields Are Required")
  }

  //checking if user exists by shecking both email and username using operator
  const existedUser = await User.findOne({
    $or: [{ username }, { email }]
  })

  if(existedUser){
    throw new ApiError(409, "user with username or email exists")
  }

  //check for images and avatar, file acess by multer
  const avatarLocalPath = req.files?.avatar[0]?.path; 
  
  //check for avatar
  if(!avatarLocalPath){
    throw new ApiError(400, "Avatar File is required")
  }
  console.log(avatarLocalPath);
  
  //upload 
  const avatar = await uploadOnCloudinary(avatarLocalPath)

  //check if uploaded
  if(!avatar){
    throw new ApiError(400, "Avatar file is required")
  }

  //entry in db
  const user = await User.create({
    fullName,
    //only url of path response from cloudinary
    avatar : avatar.url,
    email,
    password,
    username: username.toLowerCase()
  })

  //checking user using monodb id, also removing password and token
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  )
  //server error so 500
  if(!createdUser){
    throw new ApiError(500, "something went wrong while registering user")
  }

  //sending response using model created in utils
  return res.status(201).json(
    new ApiResponse(200, createdUser, "user registered Successfully")
  )
})

//login user in
const loginUser = asyncHandler(async(req, res) => {
  //req body -> data
  //username or email
  //find the user
  //password check
  //access and refresh token
  //send token as cookies

  //writing code for either email or username based login 
  const {email, username, password} = req.body

  if(!username && !email) {
    throw new ApiError(400, "username or email is required")
  }

  //finding user
  const user = await User.findOne({
    $or: [{username}, {email}]
  })
  
  if(!user){
    throw new ApiError(404, "user doesn't exist")
  }

  //check password
  const isPasswordValid = await user.isPasswordCorrect(password)

  if(!isPasswordValid){
    throw new ApiError(401, "invalid password")
  }
  
  //creating a method to generate tokens at top, then calling it
  const {accessToken, refreshToken} = await generateAccessAndRefreshTokens( user._id )
  //sending cookies to user, can use the above user or from database 
  const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

  const options = {
    httpOnly : true,
    secure : true
  }
  
  //using .cookie of res due to cookie-parser middleware to add cookies 
  return res
  .status(200)
  .cookie("accessToken", accessToken, options) 
  .cookie("refreshToken", refreshToken, options)
  .json(
    new ApiResponse(200, {
      //also returning accessToken and refreshToken if user wants to save them
      user : loggedInUser, accessToken, refreshToken
      },
      "User logged in Sucessfully"
    )
  )
})

//logging out
const logoutUser = asyncHandler(async(req,res) => {
  //due to middleware now we have access to req.user
  User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined
      }
    }
  )

  //setting option for cookies, to delete the cookies
  const options = {
    httpOnly : true,
    secure : true
  }

  return res
  .status(200)
  .clearCookie("accessToken", options)
  .clearCookie("refreshToken", options)
  .json( new ApiResponse(200, {}, "User Logged Out"))
})

//making an endpoint for user to hit to refresh it's accesstoken
const refreshAccessToken = asyncHandler(async(req, res) =>{
  //refresh token from cookies 
  const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken

  if(!incomingRefreshToken){
    throw new ApiError(401, "Unauthorized Request")
  }

  try {
    //decoding the recieved token --> now we have access of it's data
    const decodedToken = jwt.verify( 
      incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET
    )
  
    const user = await User.findById(decodedToken?._id)
  
    if(!user){
      throw new ApiError(401, "invalid refresh token")
    }
  
    //verifying refresh token
    if(incomingRefreshToken !== user?.refreshToken){
      throw new ApiError(401, "refresh token is expired or used")
    }
  
    //using method created earlier
    const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
  
    const options = {
      httpOnly : true,
      secure : true
    }
  
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newRefreshToken, options)
    .json(
      new ApiResponse(
      200, 
      {accessToken, refreshToken : newRefreshToken},
      "access token refreshed"
      )
    )
  } catch (error) {
    throw new ApiError(401, error?.message || "invalid access token")
  }
})

const changeCurrentPassword = asyncHandler(async(req, res) => {
  //he will be able to change password only if he is login -> we will use middleware for it
  const {oldPassword, newPassword} = req.body
  
  const user = await User.findById(req.user?._id)
  const isPasswordCorrect = user.isPasswordCorrect(oldPassword)

  if(!isPasswordCorrect){
    throw new ApiError(400, "Invalid Old Password")
  }

  user.password = newPassword  
  await user.save({validateBeforeSave:false}) //it will automatically hash due to pre hook, as password is modified

  return res
  .status(200)
  .json(new ApiResponse(200, {}, "Password Changed Successfully"))
}) 

const getCurrentUser = asyncHandler(async(req, res) => {
  return res
  .status(200)
  .json(new ApiResponse(200, req.user, "current user fetched successfully"))
})

const updateAccountDetails = asyncHandler(async(req, res) => {
  const {fullName, email} = req.body

  if(!fullName || !email){
    throw new ApiError(400, "All fields are required")
  }

  const user = await User.findByIdAndUpdate(req.user?._id, 
    {
      $set : {
        fullName,  //using shortcut
        email        
      }
    }, 
    {new:true}  //gives updated info after updation
  ).select("-password")

  return res.status(200)
  .json(new ApiResponse(200, user, "Account details updated successfully"))
})

//updating files
//multer + user needs to be logged in --> 2 middlewares
const updateUserAvatar = asyncHandler(async(req,res) => {
  const avatarLocalPath = req.file?.path

  if(!avatarLocalPath){
    throw new ApiError(400, "avatar file missing")
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath)

  if(!avatar.url){
    throw new ApiError(400, "Error while uploading on cloudinary") 
  }
  
  const user = await User.findByIdAndUpdate(
  req.user?._id,
  {
    $set:{
      avatar : avatar.url
    }
  },
  {new : true}
  ).select("-password")

  return res.status(200)
  .json(new ApiResponse(200, user, "Avatar updated successfully"))
})

export {registerUser, loginUser, logoutUser, refreshAccessToken, changeCurrentPassword, getCurrentUser, updateAccountDetails, updateUserAvatar} 