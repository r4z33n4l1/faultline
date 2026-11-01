// Exported handlers. One lists every person; one is scoped to the session. Not a server.
const db = {
  User: {
    findAll(query: unknown): unknown {
      return query;
    },
  },
  Record: {
    findAll(query: unknown): unknown {
      return query;
    },
  },
};

export function listPeople(_req: unknown, res: { json: (value: unknown) => void }): void {
  const rows = db.User.findAll({});
  res.json(rows);
}

export function listMine(
  req: { session: { userId: string } },
  res: { json: (value: unknown) => void },
): void {
  const { userId } = req.session;
  const rows = db.Record.findAll({ where: { ownerId: userId } });
  res.json(rows);
}
