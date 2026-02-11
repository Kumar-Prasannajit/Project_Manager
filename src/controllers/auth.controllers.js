import User from "../models/user.model.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import {sendMail, emailVerificationMailgenContent, forgotPasswordMailgenContent} from "../utils/mail.js";

const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.refreshToken = refreshToken; // Storing the refresh token in the database for future validation
        await user.save({ validateBeforeSave: false });
        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Failed to generate refresh and access token", []);
    }
};

const registerUser = asyncHandler(async (req, res) => {
    const { username, email, password, role } = req.body;

    const existingUser = await User.findOne(
        {
            $or: [{ email }, { username }]
        }
    );

    if (existingUser) {
        throw new ApiError(409, "User with this email or username already exists", []);
    }

    const user = await User.create(   //user is the document created in the database whereas User is the model of mongoose
        {
            email,
            username,
            password,
            isEmailVerified: false,
            role: role || "user"
        }
    );

    const { unhashedToken, hashedToken, TempTokenExpiry } = user.generateTemporaryToken();

    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = TempTokenExpiry;

    await user.save({ validateBeforeSave: false });

    await sendMail({
        to: user?.email,
        subject: "Email Verification - Project Manager",
        mailgenContent: emailVerificationMailgenContent(user?.username,
            `${req.protocol}://${req.get("host")}/api/v1/auth/verify-email?token=${unhashedToken}`)
    });

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken -emailVerificationToken -emailVerificationExpiry -forgotPasswordToken -forgotPasswordExpiry"
    )

    if (!createdUser) {
        throw new ApiError(500, "User registration failed", []);
    }

    return res
        .status(201)
        .json(
            new ApiResponse(201, { user: createdUser }, "User registered successfully and verification email sent")
        );
});

const loginUser = asyncHandler(async (req, res) => {
    const { email, username, password } = req.body;

    if(!email){
        throw new ApiError(400, "Email is required for login", []);
    }

    const user = await User.findOne({ email });

    if (!user) {
        throw new ApiError(404, "User not found with this email", []);
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid password", []);
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken -emailVerificationToken -emailVerificationExpiry -forgotPasswordToken -forgotPasswordExpiry"
    );

    const options = {
        httpOnly: true,
        secure: true,
    };
    
    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200, { user: loggedInUser, accessToken, refreshToken }, "User logged in successfully")
        );
});

export { registerUser, loginUser };