import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary, deleteOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefereshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(500, "Something went Wrong while generating Tokens!!");
  }
};

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

  const { fullName, email, username, password } = req.body;
  // console.log("info: ", email, fullName, username)

  // if (fullName === "") {
  //   throw new ApiError(400, "FullName is required!!")
  // }

  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required!!");
  }

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exist");
  }

  const avatarLocalPath = req.files?.avatar[0]?.path;
  // const coverImageLocalPath = req.files?.coverImage[0]?.path;

  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required!");
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar file is required!");
  }

  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went Wrong while registering User!");
  }

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User Registered Succesfully!!"));
});

const loginUser = asyncHandler(async (req, res) => {
  // req body -> data
  // username or email
  // find the user
  // password check
  // access and refresh token

  const { username, email, password } = req.body;

  if (!username && !email) {
    throw new ApiError(400, "Username or email required!!");
  }

  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (!user) {
    throw new ApiError(404, "User does not Exist!!");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Password Incorrect!!");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(
    user._id
  );
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(400)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User Logged In Successfully!!"
      )
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user_id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User Logged Out!!"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken = req.cookie.refreshToken || req.body.refreshToken

  if(!incomingRefreshToken) {
    throw new ApiError(401, "UnAuthorized Request!")
  }

  try {
    const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
  
    const user = User.findById(decodedToken?._id)
  
    if(!user) {
      throw new ApiError(401, "Invalid Refresh Token!")
    }
  
    if(incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh Token is Expired!!")
    }
  
    const options = {
      httpOnly: true,
      secure: true
    }
  
    const { accessToken, newRefreshToken } = await generateAccessAndRefereshTokens(user._id)
  
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newRefreshToken, options)
    .json(
      new  ApiResponse(
        200, 
        {
          accessToken, refreshToken: newRefreshToken
        },
        "Access Token Refreshed!"
      )
    )
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid Refresh Token!!")
  }

})

const changeCurrentPassword = asyncHandler(async(req, res) => {
  const { oldPassword, newPassword} = req.body

  const user = User.findById(req.user?._id)
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

  if(!isPasswordCorrect) {
    throw new ApiError(400, "Invalid Old Password!!")
  }

  user.password = newPassword
  user.save({validateBeforeSave: false})

  return res
  .status(200)
  .json(
    new ApiResponse(200, {}, "Password Changed Successfully!!")
  )

})

const getCurrentUser = asyncHandler(async(req, res) => {
  return res
  .status(200)
  .json(
    new ApiResponse(200, req.user, "Current User Fetched Succesfully!!")
  )
})

const updateAccountDetails = asyncHandler(async(req, res) => {
  const { fullName, email } = req.body 

  if(!fullName || !email) {
    throw new ApiError(400, "All fields are required")
  }

  const user = await User.findByIdAndUpdate(req.user?._id, 
    {
      $set: {
        fullName: fullName,
        email: email
      }
    }, 
    {new : true}
  ).select("-password")

  return res
  .status(200)
  .json(
    new ApiResponse(200, user, "Account Details updated Successfully!!")
  )

})

const updateUserAvatar = asyncHandler(async(req, res) => {
  const avatarLocalPath = req.file?.path

  if(!avatarLocalPath) {
    throw new ApiError(400, "Avatar File is Missing!!")
  }

  const deletedFile = await deleteOnCloudinary(req.user.avatar)

  if(!deletedFile) {
    throw new ApiError(401, "Error while deleting avatar Image from Cloudinary!!")
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath)

  if(!avatar.url) {
    throw new ApiError(400, "Error while Uploading the avatar in cloudinary!!")
  }

  const user = await User.findByIdAndUpdate(req.user?._id,
    {
      $set: {
        avatar: avatar.url
      }
    },
    {
      new : true
    }
  ).select("-password")

  return res
  .status(200)
  .json(
    new ApiResponse(200, user, "Avatar Updated Succesfully!!")
  )

})

const updateUserCoverImage = asyncHandler(async(req, res) => {
  const coverImageLocalPath = req.file?.path

  if(!coverImageLocalPath) {
    throw new ApiError(400, "coverImage File is Missing!!")
  }

  const deletedFile = await deleteOnCloudinary(req.user.coverImage)

  if(!deletedFile) {
    throw new ApiError(401, "Error while deleting Cover Image from Cloudinary!!")
  }

  const coverImage = await uploadOnCloudinary(coverImageLocalPath)

  if(!coverImage.url) {
    throw new ApiError(400, "Error while Uploading the coverImage in cloudinary!!")
  }

  const user = await User.findByIdAndUpdate(req.user?._id,
    {
      $set: {
        coverImage: coverImage.url
      }
    },
    {
      new : true
    }
  ).select("-password")

  return res
  .status(200)
  .json(
    new ApiResponse(200, user, "coverImage Updated Succesfully!!")
  )

})

const getUserChannelProfile = asyncHandler(async(req, res) => {
  const { username } = req.params

  if(!username?.trim()) {
    throw new ApiError(400, "username is missing!!")
  }

  const channel = await User.aggregate([
    {
      $match: {
        username: username?.toLowerCase()
      }
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers"
      }
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribedTo"
      }
    },
    {
      $addFields: {
        subscriberCount: {
          $size: "$subscribers"
        },
        channelsSubscribedToCount: {
          $size: "$subscribedTo"
        },
        isSubscribed: {
          $cond: {
            if: {$in: [req.user?._id, "$subscribers.subscriber"]},
            then: true,
            else: false
          }
        }
      }
    },
    {
      $project: {
        fullName: 1,
        username: 1,
        email: 1,
        subscriberCount: 1,
        channelsSubscribedToCount: 1,
        isSubscribed: 1,
        avatar: 1,
        coverImage: 1,

      }
    }
  ])

  if(!channel?.length) {
    throw new ApiError(404, "channel does not exist!!")
  }

  return res
  .status(200)
  .json(
    new ApiResponse(200, channel[0], "User Channel Fetched Succesfully!!")
  )

})

export { 
  registerUser, 
  loginUser, 
  logoutUser, 
  refreshAccessToken, 
  changeCurrentPassword, 
  getCurrentUser, 
  updateAccountDetails, 
  updateUserAvatar, 
  updateUserCoverImage, 
  getUserChannelProfile
};
