export interface IgnoreRule {
  negation: boolean;
  dirOnly: boolean;
  basename: boolean;
  regex: RegExp;
}

export interface IgnoreLayer {
  /** Path of the .gitignore directory relative to the inventory root. "" is the root. */
  dir: string;
  rules: IgnoreRule[];
}

export function globToRegExp(glob: string): RegExp {
  let source = "";
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index];
    if (char === undefined) {
      break;
    }
    if (char === "*") {
      if (glob[index + 1] === "*") {
        if (glob[index + 2] === "/") {
          source += "(?:.*/)?";
          index += 2;
          continue;
        }
        source += ".*";
        index += 1;
        continue;
      }
      source += "[^/]*";
      continue;
    }
    if (char === "?") {
      source += "[^/]";
      continue;
    }
    if (".+^${}()|[]\\".includes(char)) {
      source += `\\${char}`;
      continue;
    }
    source += char;
  }
  return new RegExp(`^${source}$`);
}

export function parseGitignore(text: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  for (const raw of text.split("\n")) {
    let line = raw.replace(/\r$/, "").trim();
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    let negation = false;
    if (line.startsWith("!")) {
      negation = true;
      line = line.slice(1).trim();
    }
    if (line.startsWith("\\")) {
      line = line.slice(1);
    }
    let dirOnly = false;
    if (line.endsWith("/")) {
      dirOnly = true;
      line = line.slice(0, -1);
    }
    let basename = !line.includes("/");
    if (line.startsWith("/")) {
      basename = false;
      line = line.slice(1);
    }
    if (line.length === 0) {
      continue;
    }
    rules.push({
      negation,
      dirOnly,
      basename,
      regex: globToRegExp(line),
    });
  }
  return rules;
}

function matchRules(
  rules: readonly IgnoreRule[],
  local: string,
  isDir: boolean,
): boolean | undefined {
  let result: boolean | undefined;
  const slash = local.lastIndexOf("/");
  const base = slash === -1 ? local : local.slice(slash + 1);
  for (const rule of rules) {
    if (rule.dirOnly && !isDir) {
      continue;
    }
    const target = rule.basename ? base : local;
    if (rule.regex.test(target)) {
      result = !rule.negation;
    }
  }
  return result;
}

function localPath(dir: string, rel: string): string | undefined {
  if (dir === "") {
    return rel;
  }
  const prefix = `${dir}/`;
  if (rel.startsWith(prefix)) {
    return rel.slice(prefix.length);
  }
  return undefined;
}

function decision(
  layers: readonly IgnoreLayer[],
  rel: string,
  isDir: boolean,
): boolean | undefined {
  let result: boolean | undefined;
  for (const layer of layers) {
    const local = localPath(layer.dir, rel);
    if (local === undefined || local.length === 0) {
      continue;
    }
    const layerResult = matchRules(layer.rules, local, isDir);
    if (layerResult !== undefined) {
      result = layerResult;
    }
  }
  return result;
}

/** Last matching pattern wins. A file inside an ignored directory stays ignored. */
export function isIgnored(layers: readonly IgnoreLayer[], rel: string, isDir: boolean): boolean {
  if (decision(layers, rel, isDir) === true) {
    return true;
  }
  if (isDir) {
    return false;
  }
  const parts = rel.split("/");
  for (let index = 1; index < parts.length; index += 1) {
    const parent = parts.slice(0, index).join("/");
    if (decision(layers, parent, true) === true) {
      return true;
    }
  }
  return false;
}
