import argon2 from "argon2";
import { getUserByUsername } from "./db.ts";

export async function hashPassword(password: string): Promise<string> {
    const hash = await argon2.hash(password);
    return hash;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
    const ok = await argon2.verify(stored, password);
    return ok;
}

const MAX_ATTEMPTS = 3;
const LOCK_MS = 5 * 60 * 1000;

// samo u memoriji, resetira se restartom servera
const failedAttempts = new Map<string, { count: number; lockedUntil: number }>();

export type LoginResult = {
    success: boolean;
    message: string;
    username?: string;
    locked?: boolean;
};

export async function login(username: string, password: string, vulnerable: boolean): Promise<LoginResult> {
    return vulnerable ? loginVulnerable(username, password) : loginSafe(username, password);
}

export function resetFailedAttempts(): void {
    failedAttempts.clear();
}

// ranjivo
async function loginVulnerable(username: string, password: string): Promise<LoginResult> {
    const user = await getUserByUsername(username);
    if (!user) {
        return { success: false, message: "Korisnik ne postoji." };
    }
    if (user.password !== password) {
        return { success: false, message: "Kriva lozinka." };
    }
    return { success: true, message: `Uspješna prijava kao ${user.username}.`, username: user.username };
}

// verify se racuna i za nepostojece korisnike da vrijeme odgovora ne otkriva postoji li korisnik
let dummyHash: string | undefined;

// sigurno
async function loginSafe(username: string, password: string): Promise<LoginResult> {
    const now = Date.now();
    let entry = failedAttempts.get(username);

    if (entry && now < entry.lockedUntil) {
        const minutes = Math.ceil((entry.lockedUntil - now) / 60000);
        return {
            success: false,
            locked: true,
            message: `Previše neuspjelih pokušaja. Pokušajte ponovno za ${minutes} min.`,
        };
    }
    if (entry && entry.lockedUntil !== 0) {
        failedAttempts.delete(username);
        entry = undefined;
    }

    const user = await getUserByUsername(username);
    dummyHash ??= await hashPassword("lozinka-koja-se-nikad-ne-koristi");
    const ok = await verifyPassword(password, user?.password_hash ?? dummyHash);

    if (!user || !ok) {
        // brojimo i nepostojece korisnike da zakljucavanje ne otkriva koji racuni postoje
        const count = (entry?.count ?? 0) + 1;
        const lockedUntil = count >= MAX_ATTEMPTS ? now + LOCK_MS : 0;
        failedAttempts.set(username, { count, lockedUntil });
        return { success: false, message: "Neispravno korisničko ime ili lozinka." };
    }

    failedAttempts.delete(username);
    return { success: true, message: `Uspješna prijava kao ${user.username}.`, username: user.username };
}

export const COMMON_PASSWORDS = [
    "password", "qwerty", "admin", "letmein", "111111",
    "123456", "iloveyou", "abc123", "monkey", "orange",
];

export async function dictionaryAttack(username: string, vulnerable: boolean): Promise<string[]> {
    const log: string[] = [];
    for (const [i, guess] of COMMON_PASSWORDS.entries()) {
        const result = await login(username, guess, vulnerable);
        log.push(`Pokušaj ${i + 1}: "${guess}" -> ${result.message}`);
        if (result.success) {
            log.push(`NAPAD USPJEŠAN: lozinka korisnika "${username}" je "${guess}".`);
            return log;
        }
        if (result.locked) {
            log.push("NAPAD ZAUSTAVLJEN: račun je zaključan nakon previše neuspjelih pokušaja.");
            return log;
        }
    }
    log.push("Napad nije uspio: nijedna lozinka iz rječnika nije točna.");
    return log;
}
