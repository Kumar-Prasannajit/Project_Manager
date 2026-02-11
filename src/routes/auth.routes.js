import Router from 'express';
import {registerUser} from '../controllers/auth.controllers.js';
import {loginUser} from '../controllers/auth.controllers.js';
import { validateRequest } from '../middlewares/validator.middleware.js';  
import { loginUserValidator, userRegisterValidator } from '../validators/index.js';

const router = Router();

router.route("/register").post(userRegisterValidator(), validateRequest, registerUser);
router.route("/login").post(loginUserValidator(), validateRequest, loginUser);

export default router;