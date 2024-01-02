import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { User } from "../models/user.model.js";
import { uploadOnCloud } from "../utils/cloudinary.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async(userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }

    } catch (error) {
        throw new ApiError(500,"Error at creating tokens")
    }
}

const registerUser = asyncHandler( async (req,res) => {
    // get user details from frontend (from req.body)
    // validation - nothing should be empty
    // check if user already exists
    // check for images 
    // upload images to cloudinary
    // check if avatar is successfully uploaded because it is a required field
    // create user object
    // remove password and refresh token from response (because we dont want to show them to the user)
    // check if user is created successfully
    // return response

    const {fullName, userName, email, password} = req.body

    if([fullName, userName, email, password].some((field) => field?.trim() === "")){
        throw new ApiError(400,"All fields are required")
    }

    const existingUser = await User.findOne({
        $or: [{ fullName } , { email }]
    })
    if(existingUser){
        throw new ApiError(400,"User already Exists")
    }

    const avatarPath = req.files?.avatar[0]?.path
    // const coverImagePath = req.files?.coverImage[0]?.path
    // let coverImagePath;
    // if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
    //     coverImagePath = req.files.coverImage[0].path
    // }

    let coverImagePath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImagePath = req.files.coverImage[0].path
    }

    const avatar = await uploadOnCloud(avatarPath)
    const coverImage = await uploadOnCloud(coverImagePath)

    if(!avatar){
        throw new ApiError(400,"Avatar is required")
    }

    const user = await User.create({
        fullName,
        email,
        userName: userName.toLowerCase(),
        password,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
    })

    const createdUser = await User.findById(user._id).select("-password -refreshToken")
    
    if(!createdUser){
        throw new ApiError(500,"Server problem in creating user")
    }

    return res.status(201).json(
        new ApiResponse(200,createdUser,"Successfully created the user")
    )
})

const login = asyncHandler( async (req,res) => {
    // get user details from frontend (login details from req.body)
    // validate the details
    // check if user already exists
    // decrypt the password and validate
    // generate access and refresh tokens
    // remove password and refresh token from response (because we dont want to show them to the user)
    // store tokens in form of cookies
    // return the res

    const { userName, email, password } = req.body

    if( ! (userName || email) ){
        throw new ApiError(400, "provide all details")
    }

    const user = await User.findOne({
        $or: [{userName} ,{email}]
    })

    if(!user){
        throw new ApiError(400,"User does not exist")
    }

    const validPassword = await user.isPasswordCorrect(password)

    if(!validPassword){
        throw new ApiError(400,"Please enter correct password")
    }

    const [accessToken, refreshToken] = await Promise.all([
        generateAccessAndRefreshToken(user._id).then(result => result.accessToken),
        generateAccessAndRefreshToken(user._id).then(result => result.refreshToken),
    ]);

    // const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }


    // res.setHeader("Set-Cookie", [
    //     `accessToken=${accessToken}; HttpOnly; Secure;`,
    //     `refreshToken=${refreshToken}; HttpOnly; Secure;`,
    // ]);
    

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser,
                accessToken,
                refreshToken
            },
            "User logged In Successfully"
        )
    )
})

const logout = asyncHandler( async (req, res) => {
    // get the user details (req.user) using accessToken (we can get the id from token) with the help of middleware
    // set the refresh token to undefined (deleting the token so that user doesn't stay loggedIn ==> logOut)
    // clear the cookies

    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken" ,  options)
    .clearCookie("refreshToken" , options)
    .json(new ApiResponse(
        200,
        {},
        "LoggedOut"
    ))
})

const refreshAccessToken = asyncHandler( async (req,res) => {
    // get the user details using refreshToken (we can get the id from token using req.cookies.refreshToken) we used refresh token here because the access token is expired
    // decode the token to get the userid
    // check if the existing refresh token and refresh token that was created during login are same
    // if not that means token is expired so generate new tokens
    // store tokens in form of cookies
    // return the res

    const token = req.cookies.refreshToken || req.body.refreshToken
    if(!token){
        throw new ApiError(400,"Unauthorized authentication")
    }

    try {
        const decodedToken = jwt.verify(token,process.env.REFRESH_TOKEN_SECRET)

        const user = await User.findById(decodedToken?._id)

        if(!user){
            throw new ApiError(400,"Invalid refresh token")
        }

        if(token !== user?.refreshToken){
            throw new ApiError(401,"Refresh Token is Expired")
        }

        const {accessToken,newRefreshToken} = generateAccessAndRefreshToken(user._id)

        const options = {
            httpOnly: true,
            secure: true
        }
        
        return res
        .status(200)
        .cookie("accessToken" , accessToken, options)
        .cookie("refreshToken" , newRefreshToken, options)
        .json(new ApiResponse(
            200,
            {
                accessToken,
                refreshToken: newRefreshToken
            },
            "Access Token refreshed"
        ))


    } catch (error) {
        throw new ApiError(400,"Invalid refresh Token")
    }
})

const changePassword = asyncHandler(async(req,res) => {
    // get the old password , new password and confirm password from frontend
    // check if new and confirm pass are same
    // get the user details from req.user._id
    // check if the old password is correct
    // update the new password into user password
    // save the password (during saving the new password will be automatically hashed (using "pre" middleware))
    // return the res
    
    const {oldPass , newPass , confirmPass} = req.body

    if(newPass !== confirmPass ){
        throw new ApiError(400,"Password is not matching")
    }

    const user = await User.findById(req.user?._id)

    const isCorrect = await user.isPasswordCorrect(oldPass)
    
    if(!isCorrect){
        throw new ApiError(400,"Invalid User Password")
    }

    user.password = newPass
    await user.save({ validateBeforeSave: false })

    return res
    .status(200)
    .json(new ApiResponse(
        200,
        {
            user
        },
        "User Password Changed Successfully"
    ))
})

const getUserDetails = asyncHandler(async(req,res) => {
    return res
    .status(200)
    .json(new ApiResponse(
        200,
        req.user,
        "User details Fetched"
    ))
})

const updateAccountDetails = asyncHandler(async(req,res) => {
    // get the details that are to be updated from frontend
    // make sure all the details to be updated are present and are not null
    // find the user details
    // update the details
    // return the res

    const {fullName , email} = req.body
    
    if(!fullName || !email ){
        throw new ApiError(400, "Details to be updated are required" )
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:
            {
                fullName,
                email
            }   
        },
        {
            new: true
        }
    )
    .select("-password")

    return res
    .status(200)
    .json(new ApiResponse(
        200,
        {
            fullName,
            email
        },
        "User Details updated successfully"
    ))
})

const UpdateAvatar = asyncHandler(async(req,res) => {
    // get the new avatar from frontend ( we get this from multer )
    // check if the file is there
    // upload the file on cloudinary
    // check if the upload is successful
    // find the user details
    // update the file details into user
    // return res

    const avatarPath = req.file?.path

    if(!avatarPath){
        throw new ApiError(400, "Avatar Path invalid")
    }

    const avatarUpload = await uploadOnCloud(avatarPath)

    if(!avatarUpload){
        throw new ApiError(500,"Image didn't upload successfully")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: avatarUpload.url
            }
        },
        {
            new: true
        }    
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(
        200,
        {
            user
        },
        "Avatar Uploaded successfully"
    ))
})

const UpdateCoverImage = asyncHandler(async(req,res) => {
    // get the new avatar from frontend ( we get this from multer )
    // check if the file is there
    // upload the file on cloudinary
    // check if the upload is successful
    // find the user details
    // update the file details into user
    // return res

    const coverImagePath = req.file?.path

    if(!coverImagePath){
        throw new ApiError(400, "Avatar Path invalid")
    }

    const coverImageUpload = await uploadOnCloud(coverImagePath)

    if(!coverImageUpload){
        throw new ApiError(500,"Image didn't upload successfully")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImageUpload.url
            }
        },
        {
            new: true
        }    
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(
        200,
        {
            user
        },
        "Cover Image Uploaded successfully"
    ))
})

// In profile we display the details of fullName, userName, avatar, subscriberCount(subscribers), subscriptionCount(channels)
const getchannelProfile = asyncHandler(async(req,res) => {
    // get the username from url (using req.params)
    // check if the username is valid 
    // extract the required fields using pipelines

    const {userName} = req.params

    if(!userName){
        throw new ApiError(400,"Invalid User")
    } 

    const channel = await User.aggregate([
        {
            $match: {
                userName: userName?.toLowerCase()
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
            $addFields:{
                subscriberCount:{
                    $size: "$subscribers"
                },
                subscriptionsCount:{
                    $size: "$subscribedTo"
                },
                isSubscribed:{
                    $cond:{
                        if: {$in: [req.user?._id , "$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project:{
                fullName: 1,
                userName: 1,
                avatar: 1,
                coverImage: 1,
                subscriberCount: 1,
                subscriptionsCount: 1,
                isSubscribed: 1,
                email: 1
            }
        }
    ])

    if(!channel){
        throw new ApiError(400,"Channel Doesn't exist")
    }

    return res
    .status(200)
    .json(new ApiResponse(
        200,
        channel[0],
        "User channel details fetched"
    ))
})

const getWatchHistory = asyncHandler(async(req, res) => {
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields:{
                            owner:{
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
    ])

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            user[0].watchHistory,
            "Watch history fetched successfully"
        )
    )
})

export {
    registerUser,
    login,
    logout,
    refreshAccessToken,
    changePassword,
    getUserDetails,
    updateAccountDetails,
    UpdateAvatar,
    UpdateCoverImage,
    getchannelProfile,
    getWatchHistory
}
