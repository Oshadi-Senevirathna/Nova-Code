async function uniqueCheck(uniqueness, instance, entity_name) {
  let dbAccess = require("../db_access/db_access.js");

  try {
    var unique = true;

    if (uniqueness.unique_together) {
      var filterDet = {};
      if (instance["UUID"]) {
        filterDet["UUID"] = { $ne: instance["UUID"] };
      }
      var mustCheck = true;
      for (let i = 0; i < uniqueness.unique_together.length; i++) {
        if (
          instance[uniqueness.unique_together[i]] !== "" &&
          instance[uniqueness.unique_together[i]] !== "" &&
          instance[uniqueness.unique_together[i]] !== [] &&
          instance[uniqueness.unique_together[i]] !== null &&
          instance[uniqueness.unique_together[i]] !== undefined
        ) {
          filterDet[uniqueness.unique_together[i]] =
            instance[uniqueness.unique_together[i]];
        } else {
          mustCheck = false;
        }
      }

      if (mustCheck === true) {
        const existing = await dbAccess.db
          .collection(entity_name)
          .findOne(filterDet);
        if (existing) {
          unique = false;
        }
      }
    }

    if (uniqueness.unique_seperate) {
      for (let i = 0; i < uniqueness.unique_seperate.length; i++) {
        var filterDet = {};
        if (instance["UUID"]) {
          filterDet["UUID"] = { $ne: instance["UUID"] };
        }
        if (
          instance[uniqueness.unique_seperate[i]] !== "" &&
          instance[uniqueness.unique_seperate[i]] !== [] &&
          instance[uniqueness.unique_seperate[i]] !== null &&
          instance[uniqueness.unique_seperate[i]] !== undefined
        ) {
          filterDet[uniqueness.unique_seperate[i]] =
            instance[uniqueness.unique_seperate[i]];
          const existing = await dbAccess.db
            .collection(entity_name)
            .findOne(filterDet);
          if (existing) {
            unique = false;
          }
        }
      }
    }
    return unique;
  } catch {
    return false;
  }
}

module.exports = uniqueCheck;
