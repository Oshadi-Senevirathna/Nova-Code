let express = require("express");
let dotenv = require("dotenv");
let multer = require("multer");

let dbAccess = require("../db_access/db_access.js");
let { userSessionUpdate } = require("../middleware/user_session.js");
let userLogs = require("../middleware/user_logs.js");
let { on_data_update } = require("../middleware/web_socket.js");
let verify_session_user_privilege = require("../middleware/verify_session_user_privilege.js");
let fs = require("fs");

dotenv.config();
const storageVMImage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, process.env.VM_IMAGE_LOCATION);
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});
const uploadVMImage = multer({ storage: storageVMImage });

const router = express.Router();

router.post(
  "/upload_file_to_server",
  uploadVMImage.single("file"),
  async (req, res) => {
    const entityName = req.query.entity_name;
    const payload = req.file;

    console.log(entityName, payload);

    if (!payload) {
      return res.status(400).json({
        status: false,
        reason: "No file found in request",
      });
    }

    const validation = await verify_session_user_privilege(
      req.header("Session"),
      req.header("Authorization"),
      entityName,
      true
    );
    if (!validation.status) {
      return res.status(validation.errorCode).json({
        status: false,
        reason: validation.reason,
      });
    }

    try {
      res.status(200).json({
        status: true,
        instance: { filename: payload.originalname, ...payload },
      });
    } catch (err) {
      res.status(500).json({ detail: "Error occured when accessing table" });
    }
  }
);

router.get("/check_upload_file_to_server", async (req, res) => {
  const entityName = req.query.entity_name;
  const fileName = req.query.filename;

  if (!fileName) {
    return res.status(400).json({
      status: false,
      reason: "No file name found in request",
    });
  }

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    entityName,
    true
  );

  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  try {
    const image = await dbAccess.getInstance(entityName, "filename", fileName);

    if (image.instance) {
      return res.status(400).json({
        status: false,
        reason: "A file with the same name already exists",
      });
    }

    res.status(200).json({
      status: true,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.post("/change_file_name", async (req, res) => {
  const entityName = req.body.entity_name;
  const instance = req.body.instance;

  if (!entityName || !instance) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    entityName,
    true
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
    const data = await dbAccess.getInstance(
      entityName,
      "UUID",
      instance.UUID,
      true
    );
    var file = data.instance;
    if (!file) {
      return res.status(400).json({
        status: false,
        reason: "File not found in the system",
      });
    }

    const source = file["path"];
    const folderPath = source.split("\\").slice(0, -1).join("\\");
    const target = `${folderPath}\\${instance.filename}`;

    fs.renameSync(source, target, (err) => {
      if (err) {
        console.log(err);
        return res.status(400).json({
          status: false,
          reason: "File does not exist",
        });
      }
    });

    instance["path"] = target;

    const result = await dbAccess.replaceInstance(
      entityName,
      "UUID",
      instance.UUID,
      instance,
      current_user
    );
    if (result.status !== true) {
      return res.status(400).json({ result });
    }

    userLogs(
      current_user,
      `Update instance`,
      entityName,
      instance.instance_name,
      [file]
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

    res.status(200).json({
      status: true,
      reason: "Updated file",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.post("/delete_file", async (req, res) => {
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
    true
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }
  const current_user = validation.current_user;

  console.log(`Delete file in ${entityName}`);

  try {
    const data = await dbAccess.getInstance(entityName, "UUID", UUID, true);
    var file = data.instance;
    if (!file) {
      return res.status(400).json({
        status: false,
        reason: "File not found in the system",
      });
    }

    const source = file["path"];
    fs.unlinkSync(source, function (err) {
      if (err) {
        console.log(err);
        return res.status(400).json({
          status: false,
          reason: "File does not exist",
        });
      }
    });

    var deletedEntities = new Map();
    var result = await dbAccess.deleteInstances(
      entityName,
      "UUID",
      file,
      deletedEntities
    );

    if (result.status === false) return res.status(400).json(result);

    for (const [key, value] of Object.entries(deletedEntities)) {
      const msg = {
        notification_type: "delete_entity_instance",
        payload: {
          entity_name: key,
          instances: value,
        },
      };
      on_data_update(msg);
      console.log(value[0]);
      userLogs(
        current_user,
        `Delete instance`,
        key,
        value[0].instance_name,
        value
      );
    }

    userSessionUpdate(req.header("Session"));
    res.status(200).json({
      status: true,
      reason: "Deleted file",
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.get("/download_file", async (req, res) => {
  const entityName = req.query.entity_name;
  const UUID = req.query.UUID;

  if (!entityName || !UUID) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  console.log(`Download file in ${entityName}`);

  try {
    const data = await dbAccess.getInstance(entityName, "UUID", UUID, true);
    var file = data.instance;
    if (!file) {
      return res.status(400).json({
        status: false,
        reason: "File not found in the system",
      });
    }

    const source = file["path"];
    const folderPath = source.split("\\").slice(0, -1).join("\\");
    const target = `${folderPath}\\temp\\${file.filename}`;

    return res.download(source);
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

module.exports = router;
