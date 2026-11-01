// Credential literals, query logging, and a cleartext field. Not a server. CI does not run it.
const Sequelize = function Sequelize(
  _database: string,
  _username: string,
  _password: string,
  _options: unknown,
): unknown {
  return {};
};

export const session = {
  secret: "keyboard cat",
  resave: true,
};

export const cookieSecret = "session_cookie_secret_key_here";
export const cryptoKey = "a_secure_key_for_crypto_here";
export const sampleSecret = "example-secret-value";

export function openClient(config: {
  database: string;
  username: string;
  password: string;
  host: string;
  dialect: string;
}): unknown {
  return new Sequelize(config.database, config.username, config.password, {
    host: config.host,
    dialect: config.dialect,
  });
}

export function openQuiet(config: {
  database: string;
  username: string;
  password: string;
}): unknown {
  return new Sequelize(config.database, config.username, config.password, { logging: false });
}

function encrypt(value: string): string {
  return `enc:${value}`;
}

const users = {
  update(value: unknown): unknown {
    return value;
  },
};

export function saveProfile(
  user: { ssn?: string; bankAcc?: string },
  ssn: string,
  bankAcc: string,
): unknown {
  if (ssn) {
    user.ssn = ssn;
  }
  if (bankAcc) {
    user.bankAcc = encrypt(bankAcc);
  }
  return users.update(user);
}
