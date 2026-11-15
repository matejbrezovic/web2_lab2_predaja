import pg from "pg";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

export type User = {
    id: string;
    username: string;
    email: string;
    password: string;
    password_hash: string;
}

export type PublicUser = Pick<User, "id" | "username" | "email">;

export async function getUsers(): Promise<User[]> {
    const result = await pool.query(
        `SELECT id, username, email, password
        FROM
        users ORDER BY id`
    );
    return result.rows;
}

export function buildVulnerableQuery(username: string): string {
    return `SELECT id, username, email
    FROM
    users
    WHERE username = '${username}'
    ORDER BY username`;
}

export async function searchUsersVulnerable(username: string): Promise<PublicUser[]> {
    const query = buildVulnerableQuery(username);

    const result = await pool.query(query);
    return result.rows;
}

export const SAFE_QUERY = `SELECT id, username, email
FROM
users
WHERE username = $1
ORDER BY username`;

export async function searchUsersSafe(username: string): Promise<PublicUser[]> {
    const query = SAFE_QUERY;

    const result = await pool.query(query, [username]);
    return result.rows;
}

export async function getUserByUsername(username: string): Promise<User | undefined> {
    const result = await pool.query(
        `SELECT id, username, email, password, password_hash
        FROM users
        WHERE username = $1`,
        [username]
    );
    return result.rows[0];
}
