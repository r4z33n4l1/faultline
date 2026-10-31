import type { NextFunction, Request, Response } from "express";

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const header = req.header("authorization");
  if (header === undefined || header.length === 0) {
    res.status(401).json({ error: "auth" });
    return;
  }
  next();
}

export function assertOwner(userId: string, ownerId: string): void {
  if (userId !== ownerId) {
    throw new Error("not owner");
  }
}

export function ensureTenant(userTenant: string, resourceTenant: string): void {
  if (userTenant !== resourceTenant) {
    throw new Error("not tenant");
  }
}

export function requireOwner(userId: string, ownerId: string): void {
  assertOwner(userId, ownerId);
}
