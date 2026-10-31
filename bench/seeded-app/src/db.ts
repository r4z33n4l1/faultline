export interface DeskRow {
  id: string;
  ownerId: string;
  tenantId: string;
}

async function findDocument(query: unknown): Promise<DeskRow | undefined> {
  void query;
  return undefined;
}

async function findFolder(id: string): Promise<DeskRow | undefined> {
  void id;
  return undefined;
}

async function findInvoice(query: unknown): Promise<DeskRow | undefined> {
  void query;
  return undefined;
}

async function findShare(query: unknown): Promise<DeskRow | undefined> {
  void query;
  return undefined;
}

async function runStatement(sql: string, params?: readonly unknown[]): Promise<readonly DeskRow[]> {
  void sql;
  void params;
  return [];
}

async function readNotes(filter: unknown): Promise<readonly DeskRow[]> {
  void filter;
  return [];
}

async function saveHook(row: unknown): Promise<void> {
  void row;
  return undefined;
}

export const prisma = {
  document: { findUnique: findDocument },
  folder: { findById: findFolder },
  invoice: { findOne: findInvoice },
  share: { findUnique: findShare },
};

export const db = {
  query: runStatement,
};

export const notes = {
  find: readNotes,
};

export const hooks = {
  insert: saveHook,
};
