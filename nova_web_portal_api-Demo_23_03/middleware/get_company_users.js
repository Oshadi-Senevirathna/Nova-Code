async function get_company_users(userName) {
  let dbAccess = require("../db_access/db_access.js");

  try {
    if (userName === process.env.SUPER_ADMIN) {
      /* const data = await dbAccess.getFilteredAndSortedCollection("users");

      var allUsers = data.instances;
      if (!allUsers) {
        return {
          status: false,
          instances: [],
        };
      } */
      var users = [];
      /* for (let i = 0; i < allUsers.length; i++) {
        users.push(allUsers[i].instance_name);
      } */
      return { status: true, instances: users };
    }

    const userTemp = await dbAccess.getInstance(
      "users",
      "instance_name",
      userName,
      true
    );
    const user = userTemp.instance;
    if (!user) {
      return {
        status: false,
        reason: [],
      };
    }

    const data = await dbAccess.getFilteredAndSortedCollection(
      "users",
      ["company"],
      [user.company],
      [0],
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined
    );

    var allUsers = data.instances;
    if (!allUsers) {
      return {
        status: false,
        instances: [],
      };
    }
    var users = [];
    for (let i = 0; i < allUsers.length; i++) {
      users.push(allUsers[i].instance_name);
    }
    if (users.length === 0) {
      users.push(0);
    }

    return { status: true, instances: users };
  } catch {
    return {
      status: false,
      reason: [],
    };
  }
}

module.exports = get_company_users;
