import "dotenv/config";
import express from "express";
import path from "path";
import cookieParser from "cookie-parser";
import { buildVulnerableQuery, getUserByUsername, searchUsersSafe, searchUsersVulnerable, PublicUser, SAFE_QUERY } from "./db.ts";
import { dictionaryAttack, login, resetFailedAttempts } from "./auth.ts";
import { createSession, destroySession, getSession, SESSION_COOKIE } from "./session.ts";

const app = express();
app.set("views", path.join(import.meta.dirname, "views"))
app.set("view engine", "pug");
// Render je iza HTTPS proxyja, potrebno za req.secure
app.set("trust proxy", 1);

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(async function (req, res, next) {
    const session = getSession(req.cookies[SESSION_COOKIE]);
    if (session) {
        res.locals.session = session;
        res.locals.currentUser = await getUserByUsername(session.username);
    }
    next();
});

const port = Number(process.env.PORT ?? 4080);

app.get("/", function (req, res) {
    res.render("index", {});
});

app.post("/sqlinjection", async function (req, res) {
    const usernameToSearch = String(req.body.username ?? "");
    const isVulnerable = req.body.vulnerable === "on";

    let users: PublicUser[] = [];
    let query: string = isVulnerable ? buildVulnerableQuery(usernameToSearch) : SAFE_QUERY;
    let error: string | undefined;
    try {
        if (isVulnerable) {
            users = await searchUsersVulnerable(usernameToSearch);
        } else {
            users = await searchUsersSafe(usernameToSearch);
        }
    } catch (err) {
        error = err instanceof Error ? err.message : String(err);
    }

    res.render("index", {
        sqlInjectionResults: users,
        query,
        queryParam: isVulnerable ? undefined : usernameToSearch,
        sqliVulnerable: isVulnerable,
        sqliUsername: usernameToSearch,
        sqliError: error,
    });
});

app.post("/badauth", async function (req, res) {
    const username = String(req.body.username ?? "");
    const password = String(req.body.password ?? "");
    const isVulnerable = req.body.vulnerable === "on";

    const result = await login(username, password, isVulnerable);

    if (result.success && result.username) {
        destroySession(req.cookies[SESSION_COOKIE]);
        const session = { username: result.username, vulnerableLogin: isVulnerable };
        const sessionId = createSession(session);
        res.cookie(SESSION_COOKIE, sessionId, {
            httpOnly: !isVulnerable,
            secure: !isVulnerable && req.secure,
            sameSite: "lax",
            maxAge: 60 * 60 * 1000,
        });
        res.locals.session = session;
        res.locals.currentUser = await getUserByUsername(result.username);
    }

    res.render("index", {
        authResult: result,
        authVulnerable: isVulnerable,
        authUsername: username,
    });
});

app.post("/badauth/bruteforce", async function (req, res) {
    const username = String(req.body.username ?? "");
    const isVulnerable = req.body.vulnerable === "on";

    const attackLog = await dictionaryAttack(username, isVulnerable);

    res.render("index", {
        attackLog,
        authVulnerable: isVulnerable,
        authUsername: username,
    });
});

app.post("/badauth/reset", function (req, res) {
    resetFailedAttempts();
    res.render("index", { resetDone: true });
});

app.post("/logout", function (req, res) {
    destroySession(req.cookies[SESSION_COOKIE]);
    res.clearCookie(SESSION_COOKIE);
    res.redirect("/");
});

app.listen(port, "0.0.0.0", () => {
    console.log(`Server running at http://localhost:${port}/`);
});
