let express = require("express");
let dbAccess = require("../db_access/db_access.js");
let dotenv = require("dotenv");
let groupInstances = require("../middleware/groupInstances.js");
let verify_session_user_privilege = require("../middleware/verify_session_user_privilege.js");
let get_company_users = require("../middleware/get_company_users.js");

dotenv.config();
const router = express.Router();

router.get("/dashboard_device_os", async (req, res) => {
  const tenant = req.query.tenant ? req.query.tenant : undefined;
  const companyOnly = req.query.company_only === "true" ? true : false;
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    undefined,
    undefined,
    tenant,
    companyOnly
  );

  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  try {
    const data = await dbAccess.getFilteredAndSortedCollection(
      "device",
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      validation.tenants,
      validation.users
    );
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

    res.status(200).json({
      status: true,
      instances: chartData,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.get("/dashboard_device_status", async (req, res) => {
  const tenant = req.query.tenant ? req.query.tenant : undefined;
  const companyOnly = req.query.company_only === "true" ? true : false;
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    undefined,
    undefined,
    tenant,
    companyOnly
  );

  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  try {
    const data = await dbAccess.getFilteredAndSortedCollection(
      "device",
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      validation.tenants,
      validation.users
    );
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

    res.status(200).json({
      status: true,
      instances: chartData,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.get("/dashboard_job", async (req, res) => {
  const tenant = req.query.tenant ? req.query.tenant : undefined;
  const companyOnly = req.query.company_only === "true" ? true : false;
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    undefined,
    undefined,
    tenant,
    companyOnly
  );

  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  try {
    const data = await dbAccess.getFilteredAndSortedCollection(
      "frontend_jobs",
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      validation.tenants,
      validation.users
    );
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

    res.status(200).json({
      status: true,
      instances: chartData,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing table" });
  }
});

router.get("/dashboard_count", async (req, res) => {
  const tenant = req.query.tenant ? req.query.tenant : undefined;
  const companyOnly = req.query.company_only === "true" ? true : false;
  const validation = await verify_session_user_privilege(
    req.header("Session"),
    req.header("Authorization"),
    undefined,
    undefined,
    tenant,
    companyOnly
  );

  if (!validation.status) {
    return res.status(validation.errorCode).json({
      status: false,
      reason: validation.reason,
    });
  }

  const entityName = req.query.entity_name;
  const findBy = req.query.findBy;
  const value = req.query.value;

  if (!entityName) {
    return res.status(400).json({
      status: false,
      reason: "Data missing in request",
    });
  }

  console.log(`Request filtered instances of ${entityName}`);
  try {
    const data = await dbAccess.getFilteredAndSortedCollection(
      entityName,
      [findBy],
      [value],
      [0],
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      validation.tenants,
      validation.users
    );

    if (entityName === "frontend_jobs") {
      console.log(validation);
      console.log(data);
    }

    var instances = data.instances;
    if (!instances) {
      return res.status(400).json(data);
    }

    var count = instances.length;

    res.status(200).json({
      status: true,
      instances: count,
    });
  } catch (err) {
    res.status(500).json({ detail: "Error occured when accessing db" });
  }
});

module.exports = router;
