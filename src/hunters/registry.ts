import { authzIdorHunter } from "./authz-idor.js";
import { injectionHunter } from "./injection.js";
import { secretsHunter } from "./secrets.js";
import type { Hunter } from "./types.js";

/** Append a hunter module here. One file per bug class. */
export const hunters: readonly Hunter[] = [authzIdorHunter, injectionHunter, secretsHunter];
