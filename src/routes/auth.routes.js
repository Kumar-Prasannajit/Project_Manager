import Router from 'express';
import {registerUser} from '../controllers/auth.controllers.js';
import {loginUser} from '../controllers/auth.controllers.js';
import { validateRequest } from '../middlewares/validator.middleware.js';  
import { loginUserValidator, userRegisterValidator } from '../validators/index.js';
import { verifyJWT } from '../middlewares/auth.middleware.js';
import { logoutUser } from '../controllers/auth.controllers.js';

const router = Router();

router.route("/register").post(userRegisterValidator(), validateRequest, registerUser);
router.route("/login").post(loginUserValidator(), validateRequest, loginUser);
router.route("/logout").post(verifyJWT, logoutUser);

export default router;