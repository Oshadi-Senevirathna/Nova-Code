async function check_collection_exist(collection_name) {
  let dbAccess = require("../db_access/db_access.js");

  try {
    await dbAccess.db.listCollections().toArray((error, collections) => {
      collections.forEach(function (k) {
        if (k.name === collection_name) {
          return true;
        }
      });
    });
  } catch {
    return false;
  }
}

module.exports = check_collection_exist;
