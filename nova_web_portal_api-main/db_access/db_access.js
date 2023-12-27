let mongoose = require("mongoose");
let dotenv = require("dotenv");
let check_collection_exist = require("../middleware/collection_exist.js");
let instanceDetails = require("../middleware/instance_details.js");
let reshape = require("../middleware/reshape.js");
let cleanDelete = require("../middleware/clean_delete.js");
let uniqueCheck = require("../middleware/unique_check.js");

dotenv.config();
//all gets send reshaped data except for getinstance

class DBAccess {
  constructor() {
    this.db = null;
    this.rolesUUID = new Map();
    this.roles = new Map();
    this.superAdmin = null;
    this.appAdmin = null;
  }

  connect() {
    mongoose
      .connect(process.env.DATABASE_ACCESS, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useCreateIndex: true,
      })
      .then(() => {
        // this.getPrivileges()
        console.log("Connected to reader");
      })
      .catch((error) => console.log(`${error} did not connect`));
    mongoose.set("useFindAndModify", false);
    this.db = mongoose.connection;
  }

  /* async getPrivileges()
    {
        try{
            const data = await this.getCollection('user_roles', true)
            const allRoles = data.instances
            const data_1 = await this.getCollection('user_privileges', true)
            const allPrivileges = data_1.instances
                
            const allPrivilegesArray = new Map()
            allPrivileges.forEach((item)=>{
                allPrivilegesArray.set(item.UUID, `${item.instance_name}`)

            })

            const allRolesArray = new Map()
            const rolesUUID = new Map()
            allRoles.forEach((role) => {
                var privileges = []
                role.privileges.forEach((privilege)=>{
                    privileges.push(allPrivilegesArray.get(privilege)|| privilege)
                })
                allRolesArray.set(role.UUID, privileges)
                rolesUUID.set(role.UUID,role.instance_name)
                if(role.instance_name==='Super Administrator'){
                    this.superAdmin = role.UUID
                }
                if(role.instance_name==='Application Administrator'){
                    this.appAdmin = role.UUID
                }
            }) 
            this.rolesUUID = rolesUUID
            this.roles = allRolesArray  
        }
        catch{
            return
        }
    } */

  async getCollection(entity_name, unshaped) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (!collection_exist) {
        return { status: false, reason: "The collection doesn't exist" };
      }
      const results = [];
      const result = this.db.db.collection(entity_name).find();
      await result.forEach(function (item) {
        results.push(item);
      });

      if (unshaped !== true) {
        var filterDet = {};
        filterDet["entity_name"] = entity_name;
        const shape = await this.db.db
          .collection("collection_details")
          .findOne(filterDet);
        if (shape && results) {
          return reshape(shape, results);
        }
      }

      return { status: true, instances: results };
    } catch {
      return { status: false, reason: "Was not able to access the database" };
    }
  }

  async getFieldValues(entity_name, field) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (!collection_exist) {
        return { status: false, reason: "The collection doesn't exist" };
      }

      /* const results = []; */
      const result = await this.db.db.collection(entity_name).distinct(field);
      /* await result.forEach(function (item) {
        results.push(item);
      }); */
      console.log(result);

      return { status: true, instances: result };
    } catch {
      return { status: false, reason: "Was not able to access the database" };
    }
  }
  async getCollectionSummary(entity_name) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (!collection_exist) {
        return { status: false, reason: "The collection doesn't exist" };
      }
      const results = [];
      const result = this.db.db.collection(entity_name).find();
      await result.forEach(function (item) {
        var temp = {};
        temp.UUID = item.UUID;
        temp.instance_name = item.instance_name;
        results.push(temp);
      });

      return { status: true, instances: results };
    } catch {
      return { status: false, reason: "Was not able to access the database" };
    }
  }

  async createCollection(entity_name) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (collection_exist) {
        return { status: false, reason: "The collection already exists" };
      }
      await this.db.db.createCollection(entity_name);
      return true;
    } catch {
      return;
    }
  }

  async getCollectionCount(
    entity_name,
    find_by,
    value,
    direction,
    query_string,
    query_string_fields
  ) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (!collection_exist) {
        return { status: false, reason: "The collection doesn't exist" };
      }

      var stringFilter = {};
      if (query_string !== undefined && query_string_fields !== undefined) {
        var filterDetTemp = [];
        var temp = {};
        temp["$regex"] = query_string;
        temp["$options"] = "i";
        for (let i = 0; i < query_string_fields.length; i++) {
          var filterTemp = {};
          filterTemp[query_string_fields[i]] = temp;
          filterDetTemp.push(filterTemp);
        }
        stringFilter["$or"] = filterDetTemp;
      }

      var queryFilter = {};
      if (find_by) {
        for (let i = 0; i < find_by.length; i++) {
          if (value[i] !== undefined && value[i] !== "undefined") {
            if (direction[i] === 1) {
              if (queryFilter[find_by[i]]) {
                queryFilter[find_by[i]].$gte = value[i];
              } else {
                queryFilter[find_by[i]] = { $gte: value[i] };
              }
            } else if (direction[i] === -1) {
              if (queryFilter[find_by[i]]) {
                queryFilter[find_by[i]].$lte = value[i];
              } else {
                queryFilter[find_by[i]] = { $lte: value[i] };
              }
            } else {
              if (find_by[i] !== null && find_by[i] !== undefined) {
                queryFilter[find_by[i]] = value[i];
              }
            }
          }
        }
      }

      var filter = {};
      if (
        Object.entries(stringFilter).length !== 0 &&
        Object.entries(queryFilter).length !== 0
      ) {
        filter["$and"] = [stringFilter, queryFilter];
      } else if (Object.entries(stringFilter).length !== 0) {
        filter = { ...stringFilter };
      } else if (Object.entries(queryFilter).length !== 0) {
        filter = { ...queryFilter };
      }

      var noOfInstances = 0;
      noOfInstances = await this.db.db
        .collection(entity_name)
        .find(filter)
        .count();

      return { status: true, count: noOfInstances > 0 ? noOfInstances : 0 };
    } catch {
      return { status: false, reason: "Was not able to access the database" };
    }
  }

  async getSortedCollection(
    entity_name,
    sort_by,
    direction,
    no_of_instances,
    unshaped,
    start_of_instances
  ) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (!collection_exist) {
        return { status: false, reason: "The collection doesn't exist" };
      }
      const results = [];
      var result = [];
      if (no_of_instances === null) {
        result = this.db.db
          .collection(entity_name)
          .find()
          .sort([sort_by, direction]);
      } else {
        result = this.db.db
          .collection(entity_name)
          .find()
          .sort([sort_by, direction])
          .skip(start_of_instances)
          .limit(no_of_instances);
      }

      await result.forEach(function (item) {
        results.push(item);
      });

      if (unshaped !== true) {
        var filterDet = {};
        filterDet["entity_name"] = entity_name;
        const shape = await this.db.db
          .collection("collection_details")
          .findOne(filterDet);
        if (shape && results) {
          return reshape(shape, results);
        }
      }

      return { status: true, instances: results };
    } catch {
      return { status: false, reason: "Was not able to access the database" };
    }
  }

  async getFilteredAndSortedCollection(
    entity_name,
    find_by,
    value,
    direction,
    unshaped,
    sort_by,
    sort_direction,
    no_of_instances,
    start_of_instances,
    query_string,
    query_string_fields
  ) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (!collection_exist) {
        return { status: false, reason: "The collection doesn't exist" };
      }

      var stringFilter = {};
      if (query_string !== undefined && query_string_fields !== undefined) {
        var filterDetTemp = [];
        var temp = {};
        temp["$regex"] = query_string;
        temp["$options"] = "i";
        for (let i = 0; i < query_string_fields.length; i++) {
          var filterTemp = {};
          filterTemp[query_string_fields[i]] = temp;
          filterDetTemp.push(filterTemp);
        }
        stringFilter["$or"] = filterDetTemp;
      }

      var queryFilter = {};
      if (find_by) {
        for (let i = 0; i < find_by.length; i++) {
          if (value[i] !== undefined && value[i] !== "undefined") {
            if (direction[i] === 1) {
              if (queryFilter[find_by[i]]) {
                queryFilter[find_by[i]].$gte = value[i];
              } else {
                queryFilter[find_by[i]] = { $gte: value[i] };
              }
            } else if (direction[i] === -1) {
              if (queryFilter[find_by[i]]) {
                queryFilter[find_by[i]].$lte = value[i];
              } else {
                queryFilter[find_by[i]] = { $lte: value[i] };
              }
            } else {
              if (find_by[i] !== null && find_by[i] !== undefined) {
                queryFilter[find_by[i]] = value[i];
              }
            }
          }
        }
      }

      var filter = {};
      if (
        Object.entries(stringFilter).length !== 0 &&
        Object.entries(queryFilter).length !== 0
      ) {
        filter["$and"] = [stringFilter, queryFilter];
      } else if (Object.entries(stringFilter).length !== 0) {
        filter = { ...stringFilter };
      } else if (Object.entries(queryFilter).length !== 0) {
        filter = { ...queryFilter };
      }

      console.log(filter);

      const results = [];
      const result =
        sort_by &&
        sort_direction !== undefined &&
        no_of_instances !== undefined &&
        start_of_instances !== undefined
          ? this.db.db
              .collection(entity_name)
              .find(filter)
              .sort([sort_by, sort_direction])
              .skip(start_of_instances)
              .limit(no_of_instances)
          : sort_by && sort_direction !== undefined
          ? this.db.db
              .collection(entity_name)
              .find(filter)
              .sort([sort_by, sort_direction])
          : no_of_instances !== undefined && start_of_instances !== undefined
          ? this.db.db
              .collection(entity_name)
              .find(filter)
              .skip(start_of_instances)
              .limit(no_of_instances)
          : this.db.db.collection(entity_name).find(filter);
      await result.forEach(function (item) {
        results.push(item);
      });

      var noOfInstances = 0;
      noOfInstances =
        sort_by && sort_direction !== undefined
          ? await this.db.db
              .collection(entity_name)
              .find(filter)
              .sort([sort_by, sort_direction])
              .count()
          : await this.db.db.collection(entity_name).find(filter).count();
      console.log(noOfInstances);
      if (unshaped !== true) {
        var filterDet = {};
        filterDet["entity_name"] = entity_name;
        const shape = await this.db.db
          .collection("collection_details")
          .findOne(filterDet);
        if (shape && results) {
          return reshape(shape, results);
        }
      }

      return { status: true, instances: results, count: noOfInstances };
    } catch {
      return { status: false, reason: "Was not able to access the database" };
    }
  }

  async getFilteredAndSortedCollectionSummary(
    entity_name,
    find_by,
    value,
    direction,
    sort_by,
    sort_direction
  ) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (!collection_exist) {
        return { status: false, reason: "The collection doesn't exist" };
      }

      var filter = {};
      if (find_by) {
        for (let i = 0; i < find_by.length; i++) {
          if (value[i] !== undefined && value[i] !== "undefined") {
            if (direction[i] === 1) {
              if (filter[find_by[i]]) {
                filter[find_by[i]].$gte = value[i];
              } else {
                filter[find_by[i]] = { $gte: value[i] };
              }
            } else if (direction[i] === -1) {
              if (filter[find_by[i]]) {
                filter[find_by[i]].$lte = value[i];
              } else {
                filter[find_by[i]] = { $lte: value[i] };
              }
            } else {
              if (find_by[i] !== null && find_by[i] !== undefined) {
                filter[find_by[i]] = value[i];
              }
            }
          }
        }
      }

      const results = [];
      const result =
        sort_by && sort_direction !== undefined
          ? this.db.db
              .collection(entity_name)
              .find(filter)
              .sort([sort_by, sort_direction])
          : this.db.db.collection(entity_name).find(filter);
      await result.forEach(function (item) {
        var temp = {};
        temp.UUID = item.UUID;
        temp.instance_name = item.instance_name;
        results.push(temp);
      });

      return { status: true, instances: results };
    } catch {
      return { status: false, reason: "Was not able to access the database" };
    }
  }

  async getInstance(entity_name, find_by, value, unshaped) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (!collection_exist) {
        return { status: false, reason: "The collection doesn't exist" };
      }

      var filter = {};
      filter[find_by] = value;
      const result = await this.db.db.collection(entity_name).findOne(filter);
      if (result) {
        if (unshaped !== true) {
          var filterDet = {};
          filterDet["entity_name"] = entity_name;

          const shape = await this.db.db
            .collection("collection_details")
            .findOne(filterDet);
          if (shape) {
            const data = await reshape(shape, [result]);
            if (data.instances && data.instances[0]) {
              return { status: true, instance: data.instances[0] };
            }
          }
        }
        return { status: true, instance: result };
      } else {
        return { status: false, reason: "Instance was not found" };
      }
    } catch {
      return { status: false, reason: "Was not able to access the database" };
    }
  }

  async insertInstance(entity_name, instance, current_user) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (!collection_exist) {
        return { status: false, reason: "The collection doesn't exist" };
      }

      instanceDetails(instance, current_user, "add");

      var unique = true;
      var filterDet = {};
      filterDet["entity_name"] = entity_name;
      const shape = await this.db.db
        .collection("collection_details")
        .findOne(filterDet);
      if (instance && shape && shape.uniqueness) {
        unique = await uniqueCheck(shape.uniqueness, instance, entity_name);
      }

      if (unique === true) {
        const newInstance = await this.db.db
          .collection(entity_name)
          .insertOne(instance);

        const finalInstance = { _id: newInstance._id, ...instance };

        return {
          status: true,
          reason: "Succesfully added an instance",
          instance: finalInstance,
        };
      }
      return { status: false, reason: "The entry fails the unique test" };
    } catch {
      return { status: false, reason: "Was not able to access the database" };
    }
  }

  async replaceInstance(entity_name, find_by, value, instance, current_user) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (!collection_exist) {
        return { status: false, reason: "The collection doesn't exist" };
      }

      instanceDetails(instance, current_user, "edit");

      var unique = true;
      var filterDet = {};
      filterDet["entity_name"] = entity_name;

      const shape = await this.db.db
        .collection("collection_details")
        .findOne(filterDet);

      if (instance && shape && shape.uniqueness) {
        unique = await uniqueCheck(shape.uniqueness, instance, entity_name);
      }

      if (unique === true) {
        var filter = {};
        filter[find_by] = value;

        var existing = await this.db.db.collection(entity_name).findOne(filter);
        if (!existing) {
          return res.status(400).json({
            status: false,
            reason: "Instance not found in the system",
          });
        }
        for (const [key, value] of Object.entries(instance)) {
          if (value !== undefined || value !== null) {
            existing[key] = value;
          }
        }
        const _id = existing._id;
        delete existing._id;
        const result = await this.db.db
          .collection(entity_name)
          .replaceOne(filter, existing);
        if (result.modifiedCount != 1) {
          return {
            status: false,
            reason: "Instance not found in the system at the time of update",
          };
        }

        return { status: true, instance: { ...existing, _id: _id } };
      }
      return { status: false, reason: "The entry fails the unique test" };
    } catch {
      return { status: false, reason: "Was not able to access the database" };
    }
  }

  async deleteInstances(entity_name, find_by, instance, deletedEntities) {
    try {
      const collection_exist = check_collection_exist(entity_name);
      if (!collection_exist) {
        return { status: false, reason: "The collection doesn't exist" };
      }

      var filter = {};
      filter[find_by] = instance[find_by];

      var results = [];
      const resultTemp = this.db.db.collection(entity_name).find(filter);
      await resultTemp.forEach(function (item) {
        results.push(item);
      });

      var filterDet = {};
      var deleteSuccess = true;
      var reason = "";
      filterDet["entity_name"] = entity_name;
      const shape = await this.db.db
        .collection("collection_details")
        .findOne(filterDet);
      if (shape && results && shape.referenced_entities) {
        for (let i = 0; i < shape.referenced_entities.length; i++) {
          const data = await cleanDelete(
            shape.referenced_entities[i],
            results,
            deletedEntities
          );
          deleteSuccess = data.status;
          reason = data.reason;
        }
      }

      if (deleteSuccess === true) {
        this.db.db.collection(entity_name).deleteMany(filter);
        if (deletedEntities[entity_name]) {
          deletedEntities[entity_name] = [
            ...deletedEntities[entity_name],
            ...results,
          ];
        } else {
          deletedEntities[entity_name] = results;
        }

        return {
          status: true,
          reason: "Successfully deleted",
          deletedEntities: deletedEntities,
        };
      } else {
        return { status: false, reason: reason, instance: instance };
      }
    } catch {
      return;
    }
  }
}

module.exports = new DBAccess();
