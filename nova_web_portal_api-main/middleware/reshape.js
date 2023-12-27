async function reshape(shape, instances) {
  let dbAccess = require("../db_access/db_access.js");
  const fields = shape.fields;

  try {
    const fieldVals = {};
    for (let i = 0; i < fields.length; i++) {
      const field = fields[i];
      if (field.type === "UUID_reference") {
        var mapKey = "";
        if (field.field_name_original) {
          mapKey = field.field_name;
        } else if (field.sub_field_name) {
          mapKey = field.sub_field_name;
        } else {
          mapKey = field.field_name;
        }
        fieldVals[mapKey] = new Map();

        const data = await dbAccess.getCollection(
          field.reference_entity.entity_name
        );
        const instances = data.instances;
        if (instances && instances !== undefined) {
          instances.map((instance) => {
            if (field.reference_entity.array === true) {
              for (
                let j = 0;
                j < instance[`${field.reference_entity.field_name}`].length;
                j++
              ) {
                var temp = instance[`${field.reference_entity.field_name}`][j];
                fieldVals[mapKey].set(temp["model"], temp["name"]);
              }
            } else {
              fieldVals[mapKey].set(
                instance.UUID,
                instance[`${field.reference_entity.field_name}`]
              );
            }
          });
        }
      }
    }

    const allInstances = [];
    instances.map((row) => {
      const instance = {};
      fields.map((field) => {
        var value = [];

        if (field.field_name_original && field.sub_field_name) {
          if (row[`${field.field_name_original}`]) {
            if (field.array !== true) {
              value.push(
                row[`${field.field_name_original}`][`${field.sub_field_name}`]
              );
            } else {
              value =
                row[`${field.field_name_original}`][`${field.sub_field_name}`];
            }
          }
        } else if (field.field_name_original) {
          if (field.array !== true) {
            value.push(row[`${field.field_name_original}`]);
          } else {
            value = row[`${field.field_name_original}`];
          }
        } else if (field.sub_field_name) {
          if (row[`${field.field_name}`]) {
            if (field.array !== true) {
              value.push(row[`${field.field_name}`][`${field.sub_field_name}`]);
            } else {
              value = row[`${field.field_name}`][`${field.sub_field_name}`];
            }
          }
        } else {
          if (
            field.type === "string array" ||
            field.type === "string array single"
          ) {
            var stringTemp = row[`${field.field_name}`]
              .split("[")
              .join("")
              .split("]")
              .join("")
              .split("{")
              .join("")
              .split("}")
              .join("")
              .split("'")
              .join("")
              .split(",");
            var tempArray = [];

            for (let i = 0; i < stringTemp.length; i++) {
              var tempIn = stringTemp[i].split(":");
              if (tempIn[0] === " name") {
                tempArray.push(tempIn[1]);
              }
            }
            value.push(tempArray);
          } else if (field.type === "multiple fields") {
            var temp = [];
            for (let i = 0; i < field.multiple_fields.length; i++) {
              temp = temp.concat(row[`${field.multiple_fields[i]}`].split(" "));
            }
            var temp2 = [];
            for (let j = 0; j < temp.length; j++) {
              if (
                temp[j] !== "" &&
                temp[j] !== "" &&
                temp[j] !== " " &&
                temp[j] !== " " &&
                temp[j] !== []
              ) {
                temp2.push(temp[j]);
              }
            }
            value.push(temp2);
          } else {
            if (field.array !== true) {
              value.push(row[`${field.field_name}`]);
            } else {
              value = row[`${field.field_name}`];
            }
          }
        }

        var mapKey = "";
        if (field.field_name_original) {
          mapKey = field.field_name;
        } else if (field.sub_field_name) {
          mapKey = field.sub_field_name;
        } else {
          mapKey = field.field_name;
        }

        if (fieldVals[mapKey] !== undefined && value !== undefined) {
          var temp = [];
          for (let i = 0; i < value.length; i++) {
            var temp_one = value[i];
            temp_one = fieldVals[mapKey].get(temp_one);
            if (temp_one !== undefined) {
              temp.push(temp_one);
            }
          }
          if (temp !== [] && temp !== null && temp !== undefined) {
            value = temp;
          }
        }
        if (
          value !== [] ||
          value !== "" ||
          value !== null ||
          value !== undefined
        ) {
          if (field.array === true || field.type === "multiple_fields") {
            instance[mapKey] = value;
          } else {
            instance[mapKey] = value[0];
          }
        }
      });
      instance["validation_failed"] = row["validation_failed"];
      instance["UUID"] = row["UUID"];
      instance["_id"] = row["_id"];

      allInstances.push(instance);
    });

    return { status: true, instances: allInstances };
  } catch {
    return { status: true, reason: "Was not able to reshape the data" };
  }
}

module.exports = reshape;
