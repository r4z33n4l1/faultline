// Seeded fixture. Not a server. CI does not run it.
export const db = {
  async query(_sql: string, _params?: readonly unknown[]) {
    return [];
  },
};
