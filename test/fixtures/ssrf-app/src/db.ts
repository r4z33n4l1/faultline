// Seeded fixture. Not a server. CI does not run it.
export const db = {
  async insert(_row: unknown) {
    return { id: "1" };
  },
};
