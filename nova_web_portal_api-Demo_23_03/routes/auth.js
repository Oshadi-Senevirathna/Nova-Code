let express = require("express");
let bcrypt = require("bcryptjs");
let jwt = require("jsonwebtoken");
let nodemailer = require("nodemailer");
let { v4 } = require("uuid");

let {
  get_user_from_jwt_token_reset_pwd,
  check_policy,
} = require("../middleware/auth.js");
let dbAccess = require("../db_access/db_access.js");
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
  if (!request_data.email || !request_data.pwd)
    return res.status(400).json({
      status: false,
      reason: "Not all fields have been entered",
    });

  console.log(`User authentication request recieved for ${request_data.email}`);

  try {
    const data = await dbAccess.getInstance(
      USER_COLLECTION,
      "email",
      request_data.email,
      true
    );
    var user = data.instance;

    if (!user) {
      return res.status(400).json({
        status: false,
        reason: "Invalid email",
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
      await dbAccess.replaceInstance(
        USER_COLLECTION,
        "UUID",
        user.UUID,
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
      "UUID",
      user.UUID,
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

    if (user.instance_name === process.env.SUPER_ADMIN) {
      const superadminTenantsTemp =
        await dbAccess.getFilteredAndSortedCollection("tenant");
      var superadminTenants = superadminTenantsTemp.instances;
      if (!superadminTenants) {
        user.tenants = [];
      } else {
        user.tenants = superadminTenants;
      }
      const superadminPrivilegesTemp =
        await dbAccess.getFilteredAndSortedCollection("user_privileges");
      var superadminPrivileges = superadminPrivilegesTemp.instances;
      superadminPrivileges.push({
        instance_name: "manage_companies",
        display_name: "Manage Companies",
      });
      if (!superadminPrivileges) {
        user.privileges = [];
      } else {
        user.privileges = superadminPrivileges;
      }
    } else {
      const userRoles = user.roles;
      var userPrivileges = [];
      for (let i = 0; i < userRoles.length; i++) {
        const userRoleTemp = await dbAccess.getInstance(
          "user_roles",
          "UUID",
          userRoles[i]
        );
        if (userRoleTemp.instance.privileges) {
          for (let j = 0; j < userRoleTemp.instance.privileges.length; j++) {
            userPrivileges.push(userRoleTemp.instance.privileges[j]);
          }
        }
      }
      const allPrivilegesTemp = await dbAccess.getFilteredAndSortedCollection(
        "user_privileges"
      );
      var allPrivileges = allPrivilegesTemp.instances;

      const userPrivilegesObjects = [];
      for (let j = 0; j < allPrivileges.length; j++) {
        if (userPrivileges.indexOf(allPrivileges[j].UUID) > -1) {
          userPrivilegesObjects.push(allPrivileges[j]);
        }
      }
      console.log(userPrivilegesObjects);
      user.privileges = userPrivilegesObjects;
    }
    userLogs(user["instance_name"], "User login");

    user.pwd = "";

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
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization")
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }
  const current_user = validation.current_user;

  try {
    await userSessionClose(req.body.session);
    userLogs(current_user, "User logout");

    res.status(200).json({
      status: true,
      reason: "",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when finding user" });
  }
});

router.post("/verify_user", async (req, res) => {
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    USER_COLLECTION
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

    if (user.instance_name === process.env.SUPER_ADMIN) {
      const superadminTenantsTemp =
        await dbAccess.getFilteredAndSortedCollection("tenant");
      var superadminTenants = superadminTenantsTemp.instances;
      if (!superadminTenants) {
        user.tenants = [];
      } else {
        user.tenants = superadminTenants;
      }
      const superadminPrivilegesTemp =
        await dbAccess.getFilteredAndSortedCollection("user_privileges");
      var superadminPrivileges = superadminPrivilegesTemp.instances;
      superadminPrivileges.push({
        instance_name: "manage_companies",
        display_name: "Manage Companies",
      });
      if (!superadminPrivileges) {
        user.privileges = [];
      } else {
        user.privileges = superadminPrivileges;
      }
    } else {
      const userRoles = user.roles;
      var userPrivileges = [];
      for (let i = 0; i < userRoles.length; i++) {
        const userRoleTemp = await dbAccess.getInstance(
          "user_roles",
          "UUID",
          userRoles[i]
        );
        if (userRoleTemp.instance.privileges) {
          for (let j = 0; j < userRoleTemp.instance.privileges.length; j++) {
            userPrivileges.push(userRoleTemp.instance.privileges[j]);
          }
        }
      }
      const allPrivilegesTemp = await dbAccess.getFilteredAndSortedCollection(
        "user_privileges"
      );
      var allPrivileges = allPrivilegesTemp.instances;

      const userPrivilegesObjects = [];
      for (let j = 0; j < allPrivileges.length; j++) {
        if (userPrivileges.indexOf(allPrivileges[j].UUID) > -1) {
          userPrivilegesObjects.push(allPrivileges[j]);
        }
      }
      user.privileges = userPrivilegesObjects;
    }

    res.status(200).json({
      status: true,
      jwt: req.header("Authorization"),
      session: req.header("Session"),
      reason: "",
      payload: user,
    });
  } catch (error) {
    res.status(404).json({ detail: "Error occured when accessing db" });
  }
});

router.get("/get_users", async (req, res) => {
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    USER_COLLECTION
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

    res.status(200).json({
      status: true,
      instances: users,
    });
  } catch (error) {
    res.status(404).json({ detail: "Error occured when accessing db" });
  }
});

router.post("/create_user", async (req, res) => {
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    USER_COLLECTION,
    true
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }
  const current_user = validation.current_user;

  const request_data = req.body;

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

    res.status(200).json({
      status: true,
      UUID: newId,
      reason: "",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when adding user" });
  }
});

router.post("/update_user", async (req, res) => {
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    USER_COLLECTION,
    true
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }
  const current_user = validation.current_user;

  const request_data = req.body;
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

    res.status(200).json({
      status: true,
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

    res.status(200).json({
      status: true,
      instance: user,
      reason: "",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when finding user" });
  }
});

// router.post("/forgot_password", async (req, res) => {
//   const request_data = req.body;

//   if (!request_data.username)
//     return res.status(400).json({
//       status: false,
//       reason: "Username not given",
//     });

//   console.log(
//     `Reset credentials request recieved for ${request_data.username}`
//   );

//   try {
//     const data = await dbAccess.getInstance(
//       USER_COLLECTION,
//       "instance_name",
//       request_data.username,
//       true
//     );
//     const user = data.instance;
//     if (!user) {
//       return res.status(400).json({
//         status: false,
//         reason: "No user is registered with this username",
//       });
//     }

//     const data_1 = await dbAccess.getFilteredAndSortedCollection(
//       SETTINGS_COLLECTION,
//       [SETTINGS_CATEGORY],
//       [SETTINGS_EMAIL_SETTINGS],
//       [0]
//     );
//     const emailSettings = data_1.instances;
//     if (!emailSettings) {
//       return res.status(400).json({
//         status: false,
//         reason: "Password policies are not found",
//       });
//     }

//     const emailSettingsMap = new Map();
//     emailSettings.forEach(function (item) {
//       emailSettingsMap.set(item.instance_name, item.value);
//     });

//     const transporter = nodemailer.createTransport({
//       host: emailSettingsMap.get("email_host"),
//       port: emailSettingsMap.get("email_port"),
//       auth: {
//         user: emailSettingsMap.get("email_host_user"),
//         pass: emailSettingsMap.get("email_host_password"),
//       },
//     });

//     transporter.verify().then(console.log("Verified")).catch(console.error);

//     const resetToken = jwt.sign(
//       { user: user.instance_name },
//       process.env.JWT_SECRET_PWD_RESET,
//       {
//         expiresIn: process.env.JWT_SECRET_PWD_RESET_EXPIRES_IN,
//       }
//     );
//     transporter
//       .sendMail({
//         from: `"Nova <${emailSettingsMap.get("email_host")}>`, // sender address
//         to: `${user.email}`, // list of receivers
//         subject: "Password reset request", // Subject line
//         attachments: [
//           {
//             filename: "login-logo.png",
//             path: __dirname + "/assets/login-logo.png",
//             cid: "logo", //same cid value as in the html img src
//           },
//         ],
//         html: `<p>A password reset request was made for your account.
//     To reset your password please click on the following link</p>
//     <a href=${process.env.FRONTEND_URL}/reset-password?code=${resetToken}>${process.env.FRONTEND_URL}/reset-password?code=${resetToken}</a>
//     <p>If this was not you please ignore this email</p><br/><br/><br/>
//     <img style="width:100px; float: left; margin-right: 10px;" src='cid:logo'/>
//     <p>Powered by Nova</p>
//     <br/><br/><br/>`,
//       })
//       .then((info) => {
//         userLogs(
//           user["instance_name"],
//           `Password reset request made and email setn to ${user.email}`
//         );
//       })
//       .catch(console.log("fail"));

//     res.status(200).json({
//       status: true,
//       reason: "An email was sent to your account",
//     });
//   } catch (err) {
//     res.status(500).json({ detail: "Error occured when finding user" });
//   }
// });

router.post("/forgot_password", async (req, res) => {
  const request_data = req.body;

  if (!request_data.username)
    return res.status(400).json({
      status: false,
      reason: "Username not given",
    });

  console.log(
    `Reset credentials request received for ${request_data.username}`
  );
  console.log("Username from request:", request_data.username);
  try {
    const data = await dbAccess.getInstance(
      USER_COLLECTION,
      // "instance_name",
      "email",
      request_data.username,
      true
    );

    const user = data.instance;
    console.log("User from dbAccess.getInstance:", user);
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

    // const transporter = nodemailer.createTransport({
    //   host: emailSettingsMap.get("email_host"),
    //   port: emailSettingsMap.get("email_port"),
    //   auth: {
    //     user: emailSettingsMap.get("email_host_user"),
    //     pass: emailSettingsMap.get("email_host_password"),
    //   },
    // });
    const transporter = nodemailer.createTransport({
      host: emailSettingsMap.get("email_host"),
      port: emailSettingsMap.get("email_port"),
      auth: {
        user: emailSettingsMap.get("email_host_user"),
        pass: emailSettingsMap.get("email_host_password"),
      },
      secure: false,
      tls: {
        rejectUnauthorized: false, // Allow self-signed certificates
      }, // Use false for non-secure connections
    });

    transporter
      .verify()
      .then(() => {
        console.log("Email transporter verified");
      })
      .catch((error) => {
        console.error("Email transporter verification failed:", error);
      });

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
      });

    res.status(200).json({
      status: true,
      reason: "An email was sent to your account",
    });
  } catch (err) {
    console.error("Error occurred when finding user:", err);
    res
      .status(500)
      .json({ detail: "Error occurred when finding user", error: err.message });
  }
});

module.exports = router;
