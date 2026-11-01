// Object methods that read a record by id. Not a server. CI does not run it.
const db = {
  Record: {
    find(query: unknown): unknown {
      return query;
    },
  },
};

export class Records {
  read(req: { params: { recordId: string } }, res: { json: (value: unknown) => void }): void {
    const { recordId } = req.params;
    const row = db.Record.find({ where: { id: recordId } });
    res.json(row);
  }

  remove(
    req: { params: { recordId: string }; user: { id: string } },
    res: { end: () => void },
  ): void {
    const { recordId } = req.params;
    if (recordId !== req.user.id) {
      res.end();
      return;
    }
    db.Record.find({ where: { id: recordId } });
    res.end();
  }
}
