import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"


// we write this to get the user schema details using the accessToken
const verifyJwt = asyncHandler( async(req,_,next) => {
    // get the accessToken
    // decode it to get the userid by verifying it with the token secret
    // remove password and refresh token from user (because we dont want to show them to the user)
    // save the user id into req

    
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ","")

        if(!token){
            throw new ApiError(400,"Token not found")
        }

        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

        const user = await User.findById(decodedToken?._id).select("-password -refreshToken")

        if (!user) {
            throw new ApiError(401, "Invalid Access Token")
        }
        
        req.user = user 
        next()

    } catch (error) {
        throw new ApiError(401, error?.message || "Unauthorized token")
    }
})

export {verifyJwt}