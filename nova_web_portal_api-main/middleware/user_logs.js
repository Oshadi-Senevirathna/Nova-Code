async function userLogs(user, action, entity, instance_name, instances) {
  let reshape = require("../middleware/reshape.js");
  let dbAccess = require("../db_access/db_access.js");
  let { v4 } = require("uuid");
  let { on_data_update } = require("./web_socket.js");

  const date = Date.now();
  const newId = v4();

  const payload = {};

  payload["UUID"] = newId;
  payload["instance_name"] = newId;
  payload["user"] = user;
  payload["timestamp"] = date;
  payload["collection"] = entity;
  payload["entry_name"] = instance_name;
  payload["action"] = action;

  if (instances && entity) {
    var filterDet = {};
    filterDet["entity_name"] = entity;

    const shape = await dbAccess.zzdb
      .collection("collection_details")
      .findOne(filterDet);
    if (shape) {
      const data = await reshape(shape, instances);
      for (let i = 0; i < data.instances.length; i++) {
        payload["entry"] = JSON.stringify(data.instances[i]);
        dbAccess.db.collection("logs_user").insertOne(payload);
      }
    } else {
      for (let i = 0; i < instances.length; i++) {
        payload["entry"] = JSON.stringify(instances[i]);
        dbAccess.db.collection("logs_user").insertOne(payload);
      }
    }
  } else {
    dbAccess.db.collection("logs_user").insertOne(payload);
  }

  const msg = {
    notification_type: "insert_entity_instance",
    payload: {
      entity_name: "logs_user",
      instances: [payload],
    },
  };

  on_data_update(msg);
}

module.exports = userLogs;
