async function verify_session_user_privilege(
  session_id,
  auth_id,
  entity_name,
  edit,
  tenant,
  company_only
) {
  let { get_user_from_jwt_token } = require("./auth.js");
  let check_privilege = require("./check_privilege.js");
  let { userSessionUpdate } = require("./user_session.js");
  let get_company_users = require("./get_company_users.js");

  const validSession = userSessionUpdate(session_id);
  if (!validSession)
    return {
      status: false,
      errorCode: 400,
      reason: "Session is terminated",
    };

  const current_user = get_user_from_jwt_token(auth_id);
  if (!current_user)
    return {
      status: false,
      errorCode: 400,
      reason: "Invalid authorization token",
    };

  const res = await check_privilege(current_user, entity_name, tenant, edit);
  console.log(res);
  if (!res.status && edit)
    return {
      status: false,
      errorCode: 403,
      reason: "You do not have the privileges to edit this information",
    };

  var users = [];
  if (company_only) {
    var tempUsers = await get_company_users(current_user);
    users = tempUsers.instances;
  }

  return {
    status: true,
    current_user: current_user,
    tenants: res.tenants,
    users: users,
  };
}

module.exports = verify_session_user_privilege;
