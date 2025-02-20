import { AuthService } from "../auth";
const auth = new AuthService(process.env.JWT_SECRET!);

export function expressAuthMiddleware(req, res, next) {
  try {
    const token = req.cookies.authToken || req.headers.authorization?.split(" ")[1];
    req.user = auth.validateSession(token);
    next();
  } catch (error) {
    res.status(401).json({ error: "Unauthorized" });
  }
}
