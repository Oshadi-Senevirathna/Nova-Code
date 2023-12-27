let express = require("express");
let { v4 } = require("uuid");
let nacl = require("tweetnacl");
let util = require("tweetnacl-util");
let dotenv = require("dotenv");
let FormData = require("form-data");

let dbAccess = require("../db_access/db_access.js");
let { get_user_from_jwt_token } = require("../middleware/auth.js");
let check_privilege = require("../middleware/check_privilege.js");
let { userSessionUpdate } = require("../middleware/user_session.js");
let userLogs = require("../middleware/user_logs.js");
let { on_data_update } = require("../middleware/web_socket.js");
let verify_session_user_privilege = require("../middleware/verify_session_user_privilege.js");
let formidable = require("formidable");
let fs = require("fs");

dotenv.config();
const router = express.Router();

router.post("/add_instance", async (req, res) => {
  const entityName = req.body.entity_name;
  const payload = req.body.payload;
  if (!payload || !entityName) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    entityName,
    "add"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }
  const current_user = validation.current_user;

  try {
    const newId = v4();
    payload["UUID"] = newId;

    var result = await dbAccess.insertInstance(
      entityName,
      payload,
      current_user
    );
    if (result.status !== true) {
      return res.status(400).json(result);
    }

    userLogs(
      current_user,
      `Create instance`,
      entityName,
      payload.instance_name,
      [payload]
    );
    const msg = {
      notification_type: "insert_entity_instance",
      payload: {
        entity_name: entityName,
      },
    };
    on_data_update(msg);

    userSessionUpdate(req.header("Session"));
    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      UUID: newId,
      reason: "Created instance",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.post("/update_instance", async (req, res) => {
  const entityName = req.body.entity_name;
  const payload = req.body.payload;
  if (!payload || !entityName || !payload.UUID) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    entityName,
    "edit"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }
  const current_user = validation.current_user;

  console.log(`Update instance request recieved for ${entityName}`);

  try {
    const result = await dbAccess.replaceInstance(
      entityName,
      "UUID",
      payload.UUID,
      payload,
      current_user
    );
    if (result.status !== true) {
      return res.status(400).json(result);
    }

    userLogs(
      current_user,
      `Update instance`,
      entityName,
      payload.instance_name,
      [payload]
    );

    const msg = {
      notification_type: "replace_entity_instance",
      payload: {
        entity_name: entityName,
        instances: [result.instance],
      },
    };
    on_data_update(msg);

    userSessionUpdate(req.header("Session"));
    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      reason: "Updated instance",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.post("/update_instances", async (req, res) => {
  const entityName = req.body.entity_name;
  const payload = req.body.payload;
  const UUIDs = req.body.UUIDs;
  if (!payload || !entityName || !UUIDs) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    entityName,
    "edit"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }
  const current_user = validation.current_user;

  console.log(`Update instances request recieved for ${entityName}`);

  try {
    var updatedInstances = [];

    for (let i = 0; i < UUIDs.length; i++) {
      const UUID = UUIDs[i];

      const data = await dbAccess.getInstance(entityName, "UUID", UUID, true);
      var instance = data.instance;
      if (!instance) {
        return res.status(400).json({
          status: false,
          reason: "Instance not found in the system",
        });
      }

      for (const [key, value] of Object.entries(payload)) {
        if (value !== "" && value !== undefined && value !== null) {
          instance[key] = value;
        }
      }

      const result = await dbAccess.replaceInstance(
        entityName,
        "UUID",
        instance.UUID,
        instance,
        current_user
      );
      if (result.status !== true) return res.status(400).json(result.reason);

      userLogs(
        current_user,
        `Update instance`,
        entityName,
        instance.instance_name,
        [instance]
      );
      updatedInstances.push(instance);
    }

    const msg = {
      notification_type: "replace_entity_instance",
      payload: {
        entity_name: entityName,
        instances: [updatedInstances],
      },
    };
    on_data_update(msg);

    userSessionUpdate(req.header("Session"));
    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      reason: "Updated instances",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.post("/delete_instance", async (req, res) => {
  const requestData = req.body;
  const entityName = req.body.entity_name;
  const UUID = req.body.UUID;
  if (!entityName || !UUID) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    entityName,
    "edit"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }
  const current_user = validation.current_user;

  console.log(`Delete entity request recieved for ${entityName}`);

  try {
    const data = await dbAccess.getInstance(entityName, "UUID", UUID, true);
    var instance = data.instance;
    if (!instance) {
      return res.status(400).json({
        status: false,
        reason: "Instance not found in the system",
      });
    }

    var deletedEntities = new Map();
    var result = await dbAccess.deleteInstances(
      entityName,
      "UUID",
      requestData,
      deletedEntities
    );

    if (result.status === false) return res.status(400).json(result);

    for (const [key, value] of Object.entries(deletedEntities)) {
      const msg = {
        notification_type: "delete_entity_instance",
        payload: {
          entity_name: key,
          instances: value,
          temp: "random comment",
        },
      };

      console.log("in delete");
      console.log(msg);

      on_data_update(msg);
      userLogs(
        current_user,
        `Delete instance`,
        key,
        value[0].instance_name,
        value
      );
    }

    userSessionUpdate(req.header("Session"));
    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      reason: "Deleted instances",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when acessing table" });
  }
});

router.get("/get_instance", async (req, res) => {
  const entityName = req.query.entity_name;
  const UUID = req.query.UUID;
  const instanceName = req.query.instance_name;
  const unshaped = req.query.unshaped === "true" ? true : false;
  if (!entityName || (!instanceName && !UUID)) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    entityName,
    "view"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  console.log(`Request instance of ${entityName}`);

  try {
    const data = await dbAccess.getInstance(entityName, "UUID", UUID, unshaped);
    var instance = data.instance;
    if (UUID === undefined) {
      const data_instance_name = await dbAccess.getInstance(
        entityName,
        "instance_name",
        instanceName,
        unshaped
      );
      instance = data_instance_name.instance;
    }
    if (!instance) {
      return res.status(400).json(data);
    }

    if (entityName === "users") {
      delete instance.pwd;
    }

    userSessionUpdate(req.header("Session"));
    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instance: instance,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing db" });
  }
});

router.get("/get_filtered_and_sorted_instances", async (req, res) => {
  const entityName = req.query.entity_name;
  const sortBy = req.query.sort_by;
  const sortDirection = !isNaN(Number(req.query.sort_direction))
    ? Number(req.query.sort_direction)
    : undefined;
  const unshaped = req.query.unshaped === "true" ? true : false;
  const noOfInstances = !isNaN(Number(req.query.noOfInstances))
    ? Number(req.query.noOfInstances)
    : undefined;
  const startOfInstances = !isNaN(Number(req.query.startOfInstances))
    ? Number(req.query.startOfInstances)
    : undefined;
  const findBy = req.query.findBy ? JSON.parse(req.query.findBy) : undefined;
  const value = req.query.value ? JSON.parse(req.query.value) : undefined;
  if (value) {
    for (let i = 0; i < value.length; i++) {
      if (!isNaN(Number(value[i]))) {
        value[i] = Number(value[i]);
      }
    }
  }
  console.log(req.query.direction, req.query.queryStringFields);
  const direction = req.query.direction
    ? JSON.parse(req.query.direction)
    : undefined;
  if (direction) {
    for (let i = 0; i < direction.length; i++) {
      if (!isNaN(Number(direction[i]))) {
        direction[i] = Number(direction[i]);
      }
    }
  }
  const queryString = String(req.query.queryString);
  const queryStringFields = req.query.queryStringFields
    ? JSON.parse(req.query.queryStringFields)
    : undefined;

  if (!entityName) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    entityName,
    "view"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  console.log(`Request filtered instances of ${entityName}`);

  try {
    const data = await dbAccess.getFilteredAndSortedCollection(
      entityName,
      findBy,
      value,
      direction,
      unshaped,
      sortBy,
      sortDirection,
      noOfInstances,
      startOfInstances,
      queryString,
      queryStringFields
    );
    var instances = data.instances;
    if (!instances) {
      return res.status(400).json(data);
    }

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instances: instances,
      count: data.count,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing db" });
  }
});

router.get("/get_filtered_and_sorted_instances_summary", async (req, res) => {
  const entityName = req.query.entity_name;
  const sortBy = req.query.sort_by;
  const sortDirection = !isNaN(Number(req.query.sort_direction))
    ? Number(req.query.sort_direction)
    : undefined;
  const findBy = req.query.findBy ? JSON.parse(req.query.findBy) : undefined;
  const value = req.query.value ? JSON.parse(req.query.value) : undefined;
  if (value) {
    for (let i = 0; i < value.length; i++) {
      if (!isNaN(Number(value[i]))) {
        value[i] = Number(value[i]);
      }
    }
  }
  const direction = req.query.direction
    ? JSON.parse(req.query.direction)
    : undefined;
  if (direction) {
    for (let i = 0; i < direction.length; i++) {
      if (!isNaN(Number(direction[i]))) {
        direction[i] = Number(direction[i]);
      }
    }
  }

  if (!entityName) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    entityName,
    "view"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  console.log(`Request filtered instances of ${entityName}`);

  try {
    const data = await dbAccess.getFilteredAndSortedCollectionSummary(
      entityName,
      findBy,
      value,
      direction,
      sortBy,
      sortDirection
    );
    var instances = data.instances;
    if (!instances) {
      return res.status(400).json(data);
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

router.get("/get_field_values", async (req, res) => {
  const entityName = req.query.entity_name;
  const field = req.query.field;

  if (!entityName || !field) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    entityName,
    "view"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  console.log(`Request filtered instances of ${entityName}`);

  try {
    const data = await dbAccess.getFieldValues(entityName, field);
    var instances = data.instances;
    if (!instances) {
      return res.status(400).json(data);
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

router.post("/apply_template", async (req, res) => {
  const template = req.body.template;
  const devices = req.body.devices;
  if (!template || !devices) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    "frontend_jobs",
    "add"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }
  const current_user = validation.current_user;

  console.log(`Apply template`);

  try {
    const data = await dbAccess.getFilteredAndSortedCollection(
      "vm_configs",
      ["vm_template_id"],
      [template],
      [0],
      true
    );
    var instances = data.instances;
    if (!instances) {
      return res.status(400).json(data);
    }
    console.log(instances);

    var params = [];
    for (i = 0; i < instances.length; i++) {
      var temp = {};
      temp.vm_image_id = `${process.env.BACKEND_URL}/download_file?entity_name=vm_image&UUID=${instances[i].vm_image_id}`;
      temp.memory = instances[i].memory;
      temp.vcpu = instances[i].vcpu;
      params.push(temp);
    }
    console.log(params);

    for (let i = 0; i < devices.length; i++) {
      var job = {};
      const newId = v4();
      job["UUID"] = newId;
      job.job_name = "temp job name";

      var args = [];
      args.push(params);
      args.push(devices[i].UUID);
      job.arguments = args;
      console.log(job);

      var result = await dbAccess.insertInstance(
        "frontend_jobs",
        job,
        current_user
      );

      if (result.status !== true) {
        return res.status(400).json(result);
      }

      userLogs(
        current_user,
        `Insert instance`,
        "frontend_jobs",
        job.instance_name,
        [job]
      );

      const msg = {
        notification_type: "insert_entity_instance",
        payload: {
          entity_name: "frontend_jobs",
        },
      };
      on_data_update(msg);
    }

    userSessionUpdate(req.header("Session"));
    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      reason: "Updated instance",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

module.exports = router;
