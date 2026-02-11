import { ApiResponse } from '../utils/api-response.js';
import { asyncHandler } from '../utils/async-handler.js';

// const healthCheck = (req, res) => {
//     try {
//         res
//             .status(200)
//             .json(new ApiResponse(200, { message: "Server is healthy and running." }));
//     } catch (error) {

//     }  
// };

const healthCheck = asyncHandler(async (req, res) => {
        return res
                .status(200)
                .json(new ApiResponse(200, { message: "Server is healthy and running." }));
    });

export { healthCheck };