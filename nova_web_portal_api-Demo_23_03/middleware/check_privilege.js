async function check_privilege(userName, entityName, tenant, edit) {
  let dbAccess = require("../db_access/db_access.js");
  const getPrivilege = (entity_name) => {
    switch (entity_name) {
      case "users": {
        return "manage_users";
      }
      case "user_roles": {
        return "manage_users";
      }
      case "tenant": {
        return "manage_companies";
      }
      case "company": {
        return "manage_companies";
      }
      case "device": {
        return "manage_inventory";
      }
      case "inventory": {
        return "manage_inventory";
      }
      case "frontend_job": {
        return "manage_orchestration";
      }
      case "settings": {
        return "manage_settings";
      }
      case "vm_configs": {
        return "manage_vnf";
      }
      case "vm_image": {
        return "manage_vnf";
      }
      case "vm_templates": {
        return "manage_vnf";
      }
      default:
        return "denied";
    }
  };

  try {
    if (userName === process.env.SUPER_ADMIN) {
      if (tenant === "0" || !tenant) {
        return { status: true, tenants: [] };
      } else {
        return { status: true, tenants: [tenant] };
      }
    }

    const data = await dbAccess.getInstance(
      "users",
      "instance_name",
      userName,
      true
    );
    const user = data.instance;
    if (!user) {
      return {
        status: false,
        reason: [],
      };
    }

    var allTenants = [];
    var tempTenants = user.tenants;
    for (let i = 0; i < tempTenants.length; i++) {
      allTenants.push(tempTenants[i].UUID);
    }

    var tenants = [];
    if (tenant && allTenants) {
      if (tenant === "0") {
        tenants = [...allTenants];
      } else {
        if (allTenants.indexOf(tenant) !== -1) {
          tenants.push(tenant);
        } else {
          tenants.push(0);
        }
      }
    }

    if (!edit) {
      return { status: true, tenants: tenants };
    }

    const neededPrivilege = getPrivilege(entityName);
    const userRoles = user.roles;
    const allowedRoles = dbAccess.privilegesMap.get(neededPrivilege);
    var pass = false;
    if (userRoles.length > 0 && allowedRoles.length > 0) {
      userRoles.forEach((role) => {
        if (allowedRoles.indexOf(role) > -1) {
          pass = true;
        }
      });
    }
    if (pass) {
      return { status: true, tenants: tenants };
    } else {
      return {
        status: false,
        reason: [],
      };
    }
  } catch {
    return {
      status: false,
      reason: [],
    };
  }
}

module.exports = check_privilege;
