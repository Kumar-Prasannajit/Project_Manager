import { body } from 'express-validator';

const userRegisterValidator = () => {
   return [
        body("email")
            .trim()
            .notEmpty()
            .withMessage("Email is required")
            .isEmail()
            .withMessage("Email is invalid"),

        body("username")
            .trim()
            .notEmpty()
            .withMessage("Username is required")
            .isLowercase()
            .withMessage("Username must be lowercase")
            .isLength({ min: 6 })
            .withMessage("Username must be at least 6 characters long"),

        body("password")
            .trim()
            .notEmpty()
            .withMessage("Password is required")
            .isLength({ min: 8 })
            .withMessage("Password must be at least 8 characters long"),

        body("fullName")
            .optional()
            .trim()
    ];
};

const loginUserValidator = () => {
    return [
        body("email")
            .optional()
            .notEmpty()
            .withMessage("Email is required")
            .isEmail()
            .withMessage("Email is invalid"),
        body("password")
            .trim()
            .notEmpty()
            .withMessage("Password is required")
    ];
};

export { userRegisterValidator, loginUserValidator };