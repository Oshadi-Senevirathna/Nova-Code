async function basic_auth(base64Credentials) {
  let dbAccess = require("../db_access/db_access.js");
  let bcrypt = require("bcryptjs");
  try {
    const credentials = Buffer.from(base64Credentials, "base64").toString(
      "ascii"
    );
    const [username, password] = credentials.split(":");

    const data = await dbAccess.getInstance(
      "users",
      "instance_name",
      username,
      true
    );
    const user = data.instance;

    const isMatch = await bcrypt.compare(password, user.pwd.toString());

    if (!user || !isMatch) {
      return false;
    }
    return user.instance_name;
  } catch (err) {
    return false;
  }
}

const get_user_from_jwt_token = (token) => {
  let jwt = require("jsonwebtoken");

  try {
    if (!token) return res.status(401).json({ msg: { token } });
    const jwt_payload = jwt.verify(
      token.split("Bearer ")[1],
      process.env.JWT_SECRET
    ); //if user inactive fro 10+ mins, expire
    return jwt_payload.user;
  } catch (err) {
    return false;
  }
};

const get_user_from_jwt_token_reset_pwd = (token) => {
  let jwt = require("jsonwebtoken");
  if (!token) {
    return res.status(401).json({ msg: { token } });
  }
  try {
    const jwt_payload = jwt.verify(token, process.env.JWT_SECRET_PWD_RESET);
    return jwt_payload.user;
  } catch (err) {
    return false;
  }
};

async function check_policy(pwd) {
  let dbAccess = require("../db_access/db_access.js");
  const SETTINGS_COLLECTION = "settings";
  const SETTINGS_CATEGORY = "category";
  const SETTINGS_PASSWORD_POLICIES = "password policies";

  const data = await dbAccess.getFilteredAndSortedCollection(
    SETTINGS_COLLECTION,
    [SETTINGS_CATEGORY],
    [SETTINGS_PASSWORD_POLICIES],
    [0]
  );
  const pwdPolicies = data.instances;
  if (!pwdPolicies) {
    const msg = "Password policy load failed";
    return msg;
  }

  const policies = [];
  pwdPolicies.forEach((item) => {
    policies[item.instance_name] = item.value;
  });

  var max = 0;
  var saf = 0;
  var validPwd = "^(?=";
  var cap = ".*[A-Z]".repeat(policies.min_of_capital_letters);
  var sim = ".*[a-z]".repeat(policies.min_of_simple_letters);
  var spe = ".*[!@#$&*]".repeat(policies.min_of_special_characters);
  var dig = ".*[0-9]".repeat(policies.min_of_digits);
  var len = `).{${String(policies.min_length)},}$`;

  if (policies.min_of_capital_letters > 0) {
    max = max + 1;
    cap = new RegExp(validPwd.concat(cap).concat(")"));
    saf = saf + cap.test(pwd);
  }
  if (policies.min_of_simple_letters > 0) {
    max = max + 1;
    sim = new RegExp(validPwd.concat(sim).concat(")"));
    saf = saf + sim.test(pwd);
  }
  if (policies.min_of_special_characters > 0) {
    max = max + 1;
    spe = new RegExp(validPwd.concat(spe).concat(")"));
    saf = saf + spe.test(pwd);
  }
  if (policies.min_of_digits > 0) {
    max = max + 1;
    dig = new RegExp(validPwd.concat(dig).concat(")"));
    saf = saf + dig.test(pwd);
  }
  if (policies.min_length > 0) {
    max = max + 1;
    len = new RegExp(validPwd.concat(len));
    saf = saf + len.test(pwd);
  }

  if (max === 0) {
    saf = 1;
    max = 1;
  }

  if (saf / max < 1) {
    const msg = "Password policy validation failed";
    return msg;
  }
}

module.exports = {
  basic_auth,
  get_user_from_jwt_token,
  get_user_from_jwt_token_reset_pwd,
  check_policy,
};
