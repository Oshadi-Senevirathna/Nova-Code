async function userSessionCreate(user) {
  let dbAccess = require("../db_access/db_access.js");
  let { v4 } = require("uuid");
  const date = Date.now();
  const newId = v4();

  try {
    const sessionTimeout = await dbAccess.db
      .collection("settings")
      .findOne({
        category: "session settings",
        instance_name: "session_timeout",
      });
    const maximumSessions = await dbAccess.db
      .collection("settings")
      .findOne({
        category: "session settings",
        instance_name: "maximum_sessions",
      });

    const sessions = [];
    const sessionsCursor = dbAccess.db
      .collection("user_session")
      .find({ user: user, session_closed: false });
    await sessionsCursor.forEach(function (item) {
      sessions.push(item);
    });

    for (let i = 0; i < sessions.length; i++) {
      var session = sessions[i];
      if (date - session["session_last_updated"] > sessionTimeout["value"]) {
        session["session_closed"] = true;
        await dbAccess.db
          .collection("user_session")
          .replaceOne({ session_id: session["session_id"] }, session);
      }
    }

    const totalActiveSessions = await dbAccess.db
      .collection("user_session")
      .find({ user: user, session_closed: false })
      .count();
    if (totalActiveSessions >= maximumSessions["value"]) {
      return false;
    }

    const payload = {};
    payload["session_id"] = newId;
    payload["user"] = user;
    payload["session_start"] = date;
    payload["session_last_updated"] = date;
    payload["session_closed"] = false;

    dbAccess.db.collection("user_session").insertOne(payload);

    return newId;
  } catch {
    return false;
  }
}

async function userSessionUpdate(session_id) {
  let dbAccess = require("../db_access/db_access.js");
  const date = Date.now();

  try {
    const sessionTimeout = await dbAccess.db
      .collection("settings")
      .findOne({
        category: "session settings",
        instance_name: "session_timeout",
      });
    var payload = await dbAccess.db
      .collection("user_session")
      .findOne({ session_id: session_id });

    if (payload["session_closed"] === true) {
      return false;
    }

    if (date - payload["session_last_updated"] > sessionTimeout["value"]) {
      payload["session_closed"] = true;
      await dbAccess.db
        .collection("user_session")
        .replaceOne({ session_id: session_id }, payload);
      return false;
    }

    payload["session_last_updated"] = date;
    const result = await dbAccess.db
      .collection("user_session")
      .replaceOne({ session_id: session_id }, payload);

    return result;
  } catch {
    return false;
  }
}

async function userSessionClose(session_id) {
  let dbAccess = require("../db_access/db_access.js");
  const date = Date.now();

  try {
    var payload = await dbAccess.db
      .collection("user_session")
      .findOne({ session_id: session_id });
    payload["session_last_updated"] = date;
    payload["session_closed"] = true;
    const result = await dbAccess.db
      .collection("user_session")
      .replaceOne({ session_id: session_id }, payload);

    return result;
  } catch {
    return false;
  }
}

module.exports = { userSessionCreate, userSessionUpdate, userSessionClose };
