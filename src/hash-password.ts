import { hashPassword, verifyPassword } from "./auth.ts";

console.log(await hashPassword(process.argv[2]));
