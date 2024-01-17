async function on_web_socket_connect_device(mac, ip, version) {
  const date = Date.now();
  let { v4 } = require("uuid");
  let dbAccess = require("../db_access/db_access.js");
  let userLogs = require("../middleware/user_logs.js");
  const macAdd = JSON.parse(mac);
  const ipAdd = JSON.parse(ip);

  try {
    var MACInDB = [];
    var approvedMACAdd = [];
    var approvedIPAdd = [];

    for (let i = 0; i < macAdd.length; i++) {
      const data = await dbAccess.getInstance("mac_add", "address", macAdd[i]);
      var instance = data.instance;
      if (instance) {
        MACInDB.push(macAdd[i]);
        if (instance.allowed) {
          approvedIPAdd.push(ipAdd[i]);
          approvedMACAdd.push(macAdd[i]);
        }
      }
    }

    if (MACInDB.length === 0) {
      return {
        status: false,
        reason: "Address not recognized",
      };
    }

    if (approvedMACAdd.length === 0) {
      return {
        status: false,
        reason: "Address is not cleared",
      };
    }

    const dataDevice = await dbAccess.getInstance(
      "device",
      "mac_address",
      approvedMACAdd[0],
      true
    );
    var instanceDevice = dataDevice.instance;
    if (instanceDevice) {
      return {
        status: true,
        reason: "Device already registered",
      };
    }

    var payload = {};
    const newId = v4();
    payload["UUID"] = newId;
    payload["mac_address"] = approvedMACAdd[0];
    payload["instance_name"] = approvedMACAdd[0];
    payload["ip_address"] = approvedIPAdd[0];
    payload["os_version"] = version;
    payload["last_active"] = date;
    var result = await dbAccess.insertInstance(
      "device",
      payload,
      approvedMACAdd[0]
    );
    if (result.status === true) {
      userLogs(
        approvedMACAdd[0],
        `Register device`,
        "device",
        payload.mac_address,
        [payload]
      );
      return {
        status: true,
        reason: "Registered the device",
      };
    } else {
      return {
        status: false,
        reason: "Device registration failed",
      };
    }
  } catch (err) {
    return {
      status: false,
      reason: "Database access failed",
    };
  }
}

async function on_web_socket_last_active(mac) {
  const date = Date.now();
  let dbAccess = require("../db_access/db_access.js");
  const macAdd = JSON.parse(mac);

  try {
    var MACInDB = [];
    var approvedMACAdd = [];

    for (let i = 0; i < macAdd.length; i++) {
      const data = await dbAccess.getInstance("mac_add", "address", macAdd[i]);
      var instance = data.instance;
      if (instance) {
        MACInDB.push(macAdd[i]);
        if (instance.allowed) {
          approvedMACAdd.push(macAdd[i]);
        }
      }
    }

    if (MACInDB.length === 0) {
      return {
        status: false,
        reason: "Address not recognized",
      };
    }

    if (approvedMACAdd.length === 0) {
      return {
        status: false,
        reason: "Address is not cleared",
      };
    }

    if (approvedMACAdd.length > 1) {
      return {
        status: false,
        reason: "Multiple valid addresses in single device",
      };
    }

    const dataDevice = await dbAccess.getInstance(
      "device",
      "mac_address",
      approvedMACAdd[0],
      true
    );
    var instanceDevice = dataDevice.instance;
    if (!instanceDevice) {
      return {
        status: false,
        reason: "Device not registered",
      };
    }

    instanceDevice["last_active"] = date;
    delete instanceDevice._id;
    var result = await dbAccess.replaceInstance(
      "device",
      "mac_address",
      approvedMACAdd[0],
      instanceDevice,
      approvedMACAdd[0]
    );
    if (result.status === true) {
      return {
        status: true,
        time: date,
        reason: "Updated the device",
      };
    } else {
      return {
        status: false,
        reason: "Device update failed",
      };
    }
  } catch (err) {
    return {
      status: false,
      reason: "Database access failed",
    };
  }
}

module.exports = { on_web_socket_connect_device, on_web_socket_last_active };
