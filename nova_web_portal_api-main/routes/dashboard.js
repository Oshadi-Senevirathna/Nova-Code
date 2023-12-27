let express = require("express");
let dbAccess = require("../db_access/db_access.js");
let dotenv = require("dotenv");
let groupInstances = require("../middleware/groupInstances.js");
let verify_session_user_privilege = require("../middleware/verify_session_user_privilege.js");

dotenv.config();
const router = express.Router();

router.get("/dashboard_device_os", async (req, res) => {
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    "dashboard",
    "view"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  try {
    const data = await dbAccess.getCollection("device", false);
    var instances = data.instances;
    if (!instances) {
      return res.status(400).json(data);
    }

    const vals = groupInstances(instances, "os_version");
    var chartData = {};
    var series = [];
    var labels = [];
    for (const [key, value] of Object.entries(vals)) {
      labels.push(key);
      series.push(value.length);
    }
    chartData.series = series;
    chartData.labels = labels;

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instances: chartData,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.get("/dashboard_device_status", async (req, res) => {
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    "dashboard",
    "view"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  try {
    const data = await dbAccess.getCollection("device", false);
    var instances = data.instances;
    if (!instances) {
      return res.status(400).json(data);
    }

    const date = Date.now();
    const vals = groupInstances(instances, "last_active", [
      -1,
      date - 300000,
      date - 180000,
      date,
    ]);
    var chartData = {};
    var series = [];
    var labels = [];
    for (const [key, value] of Object.entries(vals)) {
      labels.push(key);
      series.push(value.length);
    }
    chartData.series = series;
    chartData.labels = labels;

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instances: chartData,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.get("/dashboard_job", async (req, res) => {
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    "dashboard",
    "view"
  );
  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  try {
    const data = await dbAccess.getCollection("frontend_jobs", false);
    var instances = data.instances;
    if (!instances) {
      return res.status(400).json(data);
    }

    const vals = groupInstances(instances, "status");
    var chartData = {};
    var series = [];
    var labels = [];
    for (const [key, value] of Object.entries(vals)) {
      labels.push(key);
      series.push(value.length);
    }
    chartData.series = series;
    chartData.labels = labels;
    chartData.vals = vals;

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instances: chartData,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.get("/dashboard_count", async (req, res) => {
  const entityName = req.query.entity_name;
  const findBy = req.query.findBy;
  const value = req.query.value;

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
    const data = await dbAccess.getCollectionCount(
      entityName,
      [findBy],
      [value],
      [0]
    );
    var count = data.count;
    if (!count) {
      return res.status(400).json(data);
    }

    res.set("access-control-allow-origin", "*");
    res.status(200).json({
      status: true,
      instances: count,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing db" });
  }
});

module.exports = router;
