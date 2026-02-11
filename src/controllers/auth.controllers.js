import User from "../models/user.model.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import {sendMail} from "../utils/mail.js";

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

    const { unHashedToken, hashedToken, TempTokenExpiry } = user.generateTemporaryToken();

    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = TempTokenExpiry;

    await user.save({ validateBeforeSave: false });

    await sendMail({
        email: user?.email,
        subject: "Email Verification - Project Manager",
        mailgenContent: emailVerificationMailgenContent(user?.username,
            `${req.protocol}://${req.get("host")}/api/v1/auth/verify-email?token=${unHashedToken}`)
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

export { registerUser };