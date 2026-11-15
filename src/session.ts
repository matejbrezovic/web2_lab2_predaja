import { randomBytes } from "crypto";

export type Session = {
    username: string;
    vulnerableLogin: boolean;
};

const sessions = new Map<string, Session>();

export const SESSION_COOKIE = "sessionId";

export function createSession(data: Session): string {
    const id = randomBytes(32).toString("hex");
    sessions.set(id, data);
    return id;
}

export function getSession(id: string | undefined): Session | undefined {
    return id ? sessions.get(id) : undefined;
}

export function destroySession(id: string | undefined): void {
    if (id) {
        sessions.delete(id);
    }
}
