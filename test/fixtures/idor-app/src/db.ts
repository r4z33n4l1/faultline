// Seeded fixture. Not a server. CI does not run it.
export const prisma = {
  invoice: {
    async findUnique() {
      return null;
    },
  },
  order: {
    async findUnique() {
      return null;
    },
  },
  profile: {
    async findUnique() {
      return null;
    },
  },
};
