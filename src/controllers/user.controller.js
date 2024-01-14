import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"

const registerUser = asyncHandler(async (req, res) => {
  // get user details from frontend
  // validation not empty
  // check if user already exists: username or email
  // check for images, check for avatar
  // upload on cloudinary, avatar
  // create user object - create entry in db
  // remove password and refershToken field
  // check for user creation
  // return res

  const { fullName, email, username, password } = req.body
  console.log("info: ", email, fullName, username)

  // if (fullName === "") {
  //   throw new ApiError(400, "FullName is required!!")
  // }

  if(
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
      throw new ApiError(400, "All fields are required!!")
  }

  const existedUser = User.findOne({
    $or: [{ username }, { email }]
  })

  if(existedUser) {
    throw new ApiError(409, "User with email or username already exist")
  }

  const avatarLocalPath = req.files?.avatar[0]?.path;
  const coverImageLocalPath = req.files?.coverImage[0]?.path;

  if(!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required!")
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath)
  const coverImage = await uploadOnCloudinary(coverImageLocalPath)

  if(!avatar) {
    throw new ApiError(400, "Avatar file is required!")
  }

  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase()
  })

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  )

  if(!createdUser) {
    throw new ApiError(500, "Something went Wrong while registering User!")
  }

  return res.status(201).json(
    new ApiResponse(200, createdUser, "User Registered Succesfully!!")
  )

});

export { registerUser };
