import { loginSchema as authSchema } from "../validators/index.js";
import { validateRequest as validate } from "../middlewares/index.js";
import { login } from "../controllers/auth.js";
const router = express.Router();
router.post("/login", validate(authSchema), login);
router.get("/health", health);
