let express = require("express");
let bcrypt = require("bcryptjs");
let jwt = require("jsonwebtoken");
let nodemailer = require("nodemailer");
let { v4 } = require("uuid");

let {
  get_user_from_jwt_token,
  get_user_from_jwt_token_reset_pwd,
  check_policy,
} = require("../middleware/auth.js");
let dbAccess = require("../db_access/db_access.js");
let check_privilege = require("../middleware/check_privilege.js");
let userLogs = require("../middleware/user_logs.js");
let {
  userSessionCreate,
  userSessionUpdate,
  userSessionClose,
} = require("../middleware/user_session.js");
let { on_data_update } = require("../middleware/web_socket.js");
let verify_session_user_privilege = require("../middleware/verify_session_user_privilege.js");

const router = express.Router();
const USER_COLLECTION = "users";
const SETTINGS_COLLECTION = "settings";
const SETTINGS_CATEGORY = "category";
const SETTINGS_EMAIL_SETTINGS = "email settings";

router.post("/authenticate", async (req, res) => {
  const request_data = req.body;
  if (!request_data.username || !request_data.pwd)
    return res.status(400).json({
      status: false,
      reason: "Not all fields have been entered",
    });

  console.log(
    `User authentication request recieved for ${request_data.username}`
  );

  try {
    const data = await dbAccess.getInstance(
      USER_COLLECTION,
      "instance_name",
      request_data.username,
      true
    );
    var user = data.instance;
    console.log(user);

    if (!user) {
      return res.status(400).json({
        status: false,
        reason: "Invalid username",
      });
    }

    const dataWindow = await dbAccess.getInstance(
      SETTINGS_COLLECTION,
      "instance_name",
      "password_retries_window",
      true
    );
    const window = parseFloat(dataWindow.instance.value);
    const dataLockout = await dbAccess.getInstance(
      SETTINGS_COLLECTION,
      "instance_name",
      "password_lockout_time",
      true
    );
    const lockout = parseFloat(dataLockout.instance.value);
    const dataCount = await dbAccess.getInstance(
      SETTINGS_COLLECTION,
      "instance_name",
      "password_retries_allowed",
      true
    );
    const count = parseFloat(dataCount.instance.value);
    console.log(count);

    if (!lockout || !count || !window) {
      return res.status(400).json({
        status: false,
        reason: "Login policies not found",
      });
    }

    const date = Date.now();
    const timeout = user.last_login_failure_time
      ? user.last_login_failure_time + window
      : 0;
    const locked = user.locked_time ? user.locked_time : 0;

    if (date < locked) {
      return res.status(400).json({
        status: false,
        reason:
          "You exceeded the number of password retries. Please try again in a few minuites",
      });
    }

    const isMatch = await bcrypt.compare(request_data.pwd, user.pwd.toString());
    if (!isMatch) {
      if (date > timeout) {
        (user.login_failure_count = 1), (user.last_login_failure_time = date);
      } else {
        user.login_failure_count = user.login_failure_count
          ? user.login_failure_count + 1
          : 1;
        if (user.login_failure_count >= count) {
          user.locked_time = date + lockout;
          user.last_login_failure_time = date - window;
        }
      }
      console.log(user);
      await dbAccess.replaceInstance(
        USER_COLLECTION,
        "instance_name",
        user.instance_name,
        user,
        ""
      );
      return res.status(400).json({
        status: false,
        reason: "Invalid password",
      });
    }

    user.login_failure_count = 0;
    user.last_login_time = date;
    const results = await dbAccess.replaceInstance(
      USER_COLLECTION,
      "instance_name",
      user.instance_name,
      user,
      ""
    );
    if (results.status !== true) return res.status(400).json(results);

    const token = jwt.sign(
      { user: user.instance_name },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_SECRET_EXPIRES_IN,
      }
    );

    const session = await userSessionCreate(user["instance_name"]);
    if (!session)
      return res.status(400).json({
        status: false,
        reason: "Maximum active sessions exceeded",
      });

    userLogs(user["instance_name"], "User login");

    user.pwd = "";
    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      jwt: token,
      session: session,
      reason: "",
      payload: user,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when finding user" });
  }
});

router.post("/logout", async (req, res) => {
  console.log("Logout user");

  const current_user = get_user_from_jwt_token(req.header("Authorization"));
  if (!current_user)
    return res.status(400).json({
      status: false,
      reason: "Invalid authorization token",
    });

  try {
    await userSessionClose(req.body.session);
    userLogs(current_user, "User logout");

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      reason: "",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when finding user" });
  }
});

//have to minimalize from here
//verify which of these should be kept
router.get("/user_privileges", async (req, res) => {
  const validSession = userSessionUpdate(req.header("Session"));
  if (!validSession)
    return res.status(400).json({
      status: false,
      reason: "Session is terminated",
    });

  console.log("Request user privileges");

  const current_user = await get_user_from_jwt_token(
    req.header("Authorization")
  );
  if (!current_user)
    return res.status(400).json({
      status: false,
      reason: "Invalid authorization token",
    });
  try {
    const data = await dbAccess.getInstance(
      USER_COLLECTION,
      "instance_name",
      current_user,
      true
    );
    const user = data.instance;
    if (!user) {
      return res.status(400).json({
        status: false,
        reason: "User not found in the system",
      });
    }

    //have to fix this
    /* const userPrivileges = [];
    const userRoles = []
    for (const role of user.roles) {
      userRoles.push(dbAccess.rolesUUID.get(role))
      const privileges = dbAccess.roles.get(role)
      for(const privilege of privileges){
        userPrivileges.push(privilege) 
      }
    } */

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instance: { user: user, privileges: [], roles: [] },
    });
  } catch (error) {
    res.status(404).json({ detail: "Error occured when accessing db" });
  }
});

router.get("/get_roles", async (req, res) => {
  const validSession = userSessionUpdate(req.header("Session"));
  if (!validSession)
    return res.status(400).json({
      status: false,
      reason: "Session is terminated",
    });

  console.log("Request all roles");

  const current_user = get_user_from_jwt_token(req.header("Authorization"));
  if (!current_user)
    return res.status(400).json({
      status: false,
      reason: "Invalid authorization token",
    });

  try {
    const data = await dbAccess.getInstance(
      USER_COLLECTION,
      "instance_name",
      current_user,
      true
    );
    const user = data.instance;
    if (!user) {
      return res.status(400).json({
        status: false,
        reason: "User not found in the system",
      });
    }

    const isSuperAdmin =
      user.roles && user.roles.indexOf(dbAccess.superAdmin) > -1;
    const isAppAdmin = user.roles && user.roles.indexOf(dbAccess.appAdmin) > -1;

    const data_1 = await dbAccess.getCollection("user_roles");
    const roles = data_1.instances;
    if (!roles) {
      return res.status(400).json(data_1);
    }

    var filteredRoles = [];
    roles.forEach(function (role) {
      const roleIsSuperAdmin = dbAccess.superAdmin === role.UUID;
      const roleIsAppAdmin = dbAccess.appAdmin === role.UUID;
      if (isSuperAdmin && !roleIsSuperAdmin) {
        filteredRoles.push(role);
      } else if (isAppAdmin && !roleIsSuperAdmin && !roleIsAppAdmin) {
        filteredRoles.push(role);
      }
    });

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instances: filteredRoles,
    });
  } catch (error) {
    res.status(404).json({ detail: "Error occured when accessing db" });
  }
});

router.get("/get_users", async (req, res) => {
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    USER_COLLECTION,
    "view"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  try {
    const data = await dbAccess.getCollection(USER_COLLECTION);
    const users = data.instances;
    if (!users) {
      return res.status(400).json(data);
    }

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instances: users,
    });
  } catch (error) {
    res.status(404).json({ detail: "Error occured when accessing db" });
  }
});

//ad_user? what are the types of users
router.post("/create_user", async (req, res) => {
  const request_data = req.body;

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    USER_COLLECTION,
    "edit"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }
  const current_user = validation.current_user;

  try {
    const data = await dbAccess.getInstance(
      USER_COLLECTION,
      "instance_name",
      request_data.instance_name,
      true
    );
    const user = data.instance;
    if (user) {
      return res.status(400).json({
        status: false,
        reason: "User already found in the system",
      });
    }

    const policyValidation = await check_policy(request_data.pwd);
    if (policyValidation)
      return res.status(400).json({
        status: false,
        reason: policyValidation,
      });
    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(request_data.pwd, salt);
    request_data.pwd = passwordHash.toString("binary");

    const newId = v4();
    request_data["UUID"] = newId;

    const result = await dbAccess.insertInstance(
      USER_COLLECTION,
      request_data,
      current_user
    );
    if (result.status !== true) return res.status(400).json(result.reason);

    userLogs(
      current_user,
      "Create user",
      USER_COLLECTION,
      result.instance.instance_name,
      [result.instance]
    );
    const msg = {
      notification_type: "insert_entity_instance",
      payload: {
        entity_name: USER_COLLECTION,
      },
    };
    on_data_update(msg);

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      UUID: newId,
      reason: "",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when adding user" });
  }
});

//findone and replaceone in users
router.post("/update_user", async (req, res) => {
  const request_data = req.body;

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    USER_COLLECTION,
    "edit"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }
  const current_user = validation.current_user;

  console.log(`User update request recieved for"${request_data.instance_name}`);

  try {
    const data = await dbAccess.getInstance(
      USER_COLLECTION,
      "instance_name",
      request_data.instance_name,
      true
    );

    const user = data.instance;
    if (!user) {
      return res.status(400).json({
        status: false,
        reason: "User not found in the system",
      });
    }

    if (request_data.old_pwd && request_data.new_pwd) {
      const isMatch = await bcrypt.compare(
        request_data.old_pwd,
        user.pwd.toString()
      );
      if (!isMatch) {
        return res.status(400).json({
          status: false,
          reason: "Invalid old password",
        });
      }

      const policyValidation = await check_policy(request_data.new_pwd);
      if (policyValidation)
        return res.status(400).json({
          status: false,
          reason: policyValidation,
        });

      const salt = await bcrypt.genSalt();
      const passwordHash = await bcrypt.hash(request_data.new_pwd, salt);
      request_data.pwd = passwordHash.toString("binary");
      delete request_data.old_pwd;
      delete request_data.new_pwd;
      console.log(request_data);
    }

    const result = await dbAccess.replaceInstance(
      USER_COLLECTION,
      "instance_name",
      request_data.instance_name,
      request_data,
      current_user
    );
    console.log(result);
    if (result.status !== true) return res.status(400).json(result.reason);

    userLogs(
      current_user,
      "Update instance",
      USER_COLLECTION,
      result.instance.instance_name,
      [result.instance]
    );
    const msg = {
      notification_type: "replace_entity_instance",
      payload: {
        entity_name: USER_COLLECTION,
        instances: [request_data.UUID],
      },
    };
    on_data_update(msg);

    console.log("end");
    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      reason: "",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when finding user" });
  }
});

//delete many in users
router.post("/delete_user", async (req, res) => {
  const validSession = userSessionUpdate(req.header("Session"));
  if (!validSession)
    return res.status(400).json({
      status: false,
      reason: "Session is terminated",
    });

  const current_user = get_user_from_jwt_token(req.header("Authorization"));

  if (!current_user)
    return res.status(400).json({
      status: false,
      reason: "Invalid authorization token",
    });

  const request_data = req.body;

  if (!request_data.instance_name)
    return res.status(400).json({
      status: false,
      reason: "Username not given",
    });

  console.log(`User delete request recieved for"${request_data.instance_name}`);

  try {
    const check = await check_privilege(current_user, "Manage Users");
    if (!check)
      return res.status(403).json({
        status: false,
        reason: "Encountered an error when accessing the database",
      });

    var deletedEntities = [];
    const result = await dbAccess.deleteInstances(
      USER_COLLECTION,
      "instance_name",
      request_data,
      deletedEntities
    );
    if (result.status === false) return res.status(400).json(result);

    for (let i = 0; i < result.deletedEntities.length; i++) {
      const msg = {
        notification_type: "delete_entity_instance",
        payload: {
          entity_name: result.deletedEntities[i],
        },
      };
      on_data_update(msg);
      userLogs(current_user, "Delete instance", USER_COLLECTION, "", [
        result.deletedEntities[i],
      ]);
    }

    res.set("access-control-allow-origin", "*");
    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({ detail: "Error occured when finding user" });
  }
});

router.post("/delete_role", async (req, res) => {
  const validSession = userSessionUpdate(req.header("Session"));
  if (!validSession)
    return res.status(400).json({
      status: false,
      reason: "Session is terminated",
    });

  const current_user = get_user_from_jwt_token(req.header("Authorization"));

  if (!current_user)
    return res.status(400).json({
      status: false,
      reason: "Invalid authorization token",
    });

  const request_data = req.body;

  if (!request_data.UUID)
    return res.status(400).json({
      status: false,
      reason: "Role not given",
    });

  console.log(`Role delete request recieved`);

  try {
    const check = await check_privilege(current_user, "Manage Users");
    if (!check)
      return res.status(403).json({
        status: false,
        reason: "Encountered an error when accessing the database",
      });

    const data = await dbAccess.getInstance(
      "user_roles",
      "UUID",
      request_data.UUID,
      true
    );
    var instance = data.instance;
    if (!instance) {
      return res.status(400).json({
        status: false,
        reason: "Role not found in the system",
      });
    }

    const data_1 = await dbAccess.getFilteredAndSortedCollection(
      "users",
      ["roles"],
      [request_data.UUID],
      [0],
      true
    );
    const usersWithRole = data_1.instances;
    var canDeleteRole = true;
    for (let i = 0; i < usersWithRole.length; i++) {
      var user = usersWithRole[i];
      if (user.roles.length === 1) {
        canDeleteRole = false;
        break;
      } else {
        const roles = user.roles;
        const index = roles.indexOf(request_data.UUID);
        if (index > -1) {
          roles.splice(index, 1);
        }
        user["roles"] = roles;
        await dbAccess.replaceInstance(
          USER_COLLECTION,
          "instance_name",
          user.instance_name,
          user,
          current_user
        );
        const msg = {
          notification_type: "replace_entity_instance",
          payload: {
            entity_name: USER_COLLECTION,
            UUID: user.UUID,
          },
        };
        on_data_update(msg);
      }
    }

    if (canDeleteRole === false) {
      return res.status(400).json({
        status: false,
        reason: "Cannot delete the role due to dependencies",
      });
    }

    var deletedEntities = [];
    const result = await dbAccess.deleteInstances(
      "user_roles",
      "UUID",
      instance,
      deletedEntities
    );
    if (result.status === false) return res.status(400).json(result);

    for (let i = 0; i < result.deletedEntities.length; i++) {
      const msg = {
        notification_type: "delete_entity_instance",
        payload: {
          entity_name: result.deletedEntities[i],
        },
      };
      on_data_update(msg);
      userLogs(current_user, "Delete instance", "user_roles", "", [
        result.deletedEntities[i],
      ]);
    }

    res.set("access-control-allow-origin", "*");
    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({ detail: "Error occured when finding user" });
  }
});

router.post("/change_credentials", async (req, res) => {
  const validSession = userSessionUpdate(req.header("Session"));
  if (!validSession)
    return res.status(400).json({
      status: false,
      reason: "Session is terminated",
    });

  const current_user = get_user_from_jwt_token(req.header("Authorization"));

  if (!current_user)
    return res.status(400).json({
      status: false,
      reason: "Invalid authorization token",
    });

  const request_data = req.body;

  if (!request_data.pwd)
    return res.status(400).json({
      status: false,
      reason: "Password not given",
    });

  if (!request_data.new_pwd)
    return res.status(400).json({
      status: false,
      reason: "New password not given",
    });

  console.log(`Change credentials request recieved for ${current_user}`);

  try {
    const data = await dbAccess.getInstance(
      USER_COLLECTION,
      "instance_name",
      current_user,
      true
    );
    const user = data.instance;
    if (!user) {
      return res.status(400).json({
        status: false,
        reason: "User not found in the system",
      });
    }

    const isMatch = await bcrypt.compare(request_data.pwd, user.pwd.toString());
    if (!isMatch)
      return res.status(400).json({
        status: false,
        reason: "Wrong current password",
      });

    const policyValidation = await check_policy(request_data.new_pwd);
    if (policyValidation)
      return res.status(400).json({
        status: false,
        reason: policyValidation,
      });

    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(request_data.new_pwd, salt);
    user.pwd = passwordHash.toString("binary");

    const result = await dbAccess.replaceInstance(
      USER_COLLECTION,
      "instance_name",
      current_user,
      user,
      current_user
    );
    if (result.status !== true) return res.status(400).json(result.status);

    userLogs(
      current_user,
      "Change user credentials",
      USER_COLLECTION,
      current_user,
      [result.instance]
    );
    const msg = {
      notification_type: "replace_entity_instance",
      payload: {
        entity_name: USER_COLLECTION,
        UUID: user.UUID,
      },
    };
    on_data_update(msg);

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instance: result.instance,
      reason: "",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when finding user" });
  }
});

router.post("/reset_password", async (req, res) => {
  const request_data = req.body;

  if (!request_data.code)
    return res.status(400).json({
      status: false,
      reason: "Reset code not given",
    });

  const current_user = get_user_from_jwt_token_reset_pwd(request_data.code);
  if (!current_user) {
    return res.status(400).json({
      status: false,
      reason: "Your token has either expired or is invalid",
    });
  }

  if (!request_data.pwd)
    return res.status(400).json({
      status: false,
      reason: "Password not given",
    });

  console.log(`Reset password request recieved for ${current_user}`);

  try {
    const data = await dbAccess.getInstance(
      USER_COLLECTION,
      "instance_name",
      current_user,
      true
    );
    const user = data.instance;
    if (!user) {
      return res.status(400).json({
        status: false,
        reason: "User not found in the system",
      });
    }

    const policyValidation = await check_policy(request_data.pwd);
    if (policyValidation)
      return res.status(400).json({
        status: false,
        reason: "Password policy validation failed",
      });

    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(request_data.pwd, salt);
    user.pwd = passwordHash.toString("binary");

    const result = await dbAccess.replaceInstance(
      USER_COLLECTION,
      "instance_name",
      current_user,
      user,
      current_user
    );
    if (result.status !== true) return res.status(400).json(result);

    userLogs(current_user, "Reset password", USER_COLLECTION, current_user, [
      result.instance,
    ]);
    const msg = {
      notification_type: "replace_entity_instance",
      payload: {
        entity_name: USER_COLLECTION,
        UUID: user.UUID,
      },
    };
    on_data_update(msg);

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instance: user,
      reason: "",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when finding user" });
  }
});

router.post("/forgot_password", async (req, res) => {
  const request_data = req.body;

  if (!request_data.username)
    return res.status(400).json({
      status: false,
      reason: "Username not given",
    });

  console.log(
    `Reset credentials request recieved for ${request_data.username}`
  );

  try {
    const data = await dbAccess.getInstance(
      USER_COLLECTION,
      "instance_name",
      request_data.username,
      true
    );
    const user = data.instance;
    if (!user) {
      return res.status(400).json({
        status: false,
        reason: "No user is registered with this username",
      });
    }

    const data_1 = await dbAccess.getFilteredAndSortedCollection(
      SETTINGS_COLLECTION,
      [SETTINGS_CATEGORY],
      [SETTINGS_EMAIL_SETTINGS],
      [0]
    );
    const emailSettings = data_1.instances;
    if (!emailSettings) {
      return res.status(400).json({
        status: false,
        reason: "Password policies are not found",
      });
    }

    const emailSettingsMap = new Map();
    emailSettings.forEach(function (item) {
      emailSettingsMap.set(item.instance_name, item.value);
    });

    const transporter = nodemailer.createTransport({
      host: emailSettingsMap.get("email_host"),
      port: emailSettingsMap.get("email_port"),
      auth: {
        user: emailSettingsMap.get("email_host_user"),
        pass: emailSettingsMap.get("email_host_password"),
      },
    });

    transporter.verify().then(console.log("Verified")).catch(console.error);

    const resetToken = jwt.sign(
      { user: user.instance_name },
      process.env.JWT_SECRET_PWD_RESET,
      {
        expiresIn: process.env.JWT_SECRET_PWD_RESET_EXPIRES_IN,
      }
    );
    transporter
      .sendMail({
        from: `"Nova <${emailSettingsMap.get("email_host")}>`, // sender address
        to: `${user.email}`, // list of receivers
        subject: "Password reset request", // Subject line
        attachments: [
          {
            filename: "login-logo.png",
            path: __dirname + "/assets/login-logo.png",
            cid: "logo", //same cid value as in the html img src
          },
        ],
        html: `<p>A password reset request was made for your account. 
    To reset your password please click on the following link</p>
    <a href=${process.env.FRONTEND_URL}/reset-password?code=${resetToken}>${process.env.FRONTEND_URL}/reset-password?code=${resetToken}</a>
    <p>If this was not you please ignore this email</p><br/><br/><br/>
    <img style="width:100px; float: left; margin-right: 10px;" src='cid:logo'/>
    <p>Powered by Nova</p>
    <br/><br/><br/>`,
      })
      .then((info) => {
        userLogs(
          user["instance_name"],
          `Password reset request made and email setn to ${user.email}`
        );
      })
      .catch(console.log("fail"));

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      reason: "An email was sent to your account",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when finding user" });
  }
});

router.get("/get_password_settings", async (req, res) => {
  const validSession = userSessionUpdate(req.header("Session"));
  if (!validSession)
    return res.status(400).json({
      status: false,
      reason: "Session is terminated",
    });

  console.log("Request password settings");

  const current_user = get_user_from_jwt_token(req.header("Authorization"));
  if (!current_user)
    return res.status(400).json({
      status: false,
      reason: "Invalid authorization token",
    });

  try {
    const data = await dbAccess.getFilteredAndSortedCollection(
      "settings",
      ["category"],
      ["password policies"],
      [0],
      false
    );
    const instances = data.instances;
    if (!instances) {
      return res.status(400).json({
        status: false,
        reason: "Instances not found in the system",
      });
    }

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instances: instances,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing db" });
  }
});

module.exports = router;
