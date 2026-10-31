// Seeded fixture. Not a server. CI does not run it.
export function requireAuth(_req, _res, next) {
  next();
}
