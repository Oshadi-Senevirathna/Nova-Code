const groupInstances = (
  instances,
  field,
  range,
  intervalStart,
  intervalEnd,
  interval
) => {
  var groupedInstances = new Map();

  if (intervalStart && intervalEnd && interval) {
    const noOfIntervals = Math.ceil((intervalEnd - intervalStart) / interval);

    for (let j = 0; j < noOfIntervals; j++) {
      groupedInstances[intervalStart + interval * j] = [];
    }

    for (const [key, value] of Object.entries(groupedInstances)) {
      for (let i = 0; i < instances.length; i++) {
        const instance = instances[i];
        const keyInt = parseFloat(key);
        if (instance[field] > keyInt && instance[field] < keyInt + interval) {
          var temp = value;
          temp.push(instance);
          groupedInstances[key] = temp;
        }
      }
    }
    return groupedInstances;
  }

  if (range) {
    for (let j = 0; j < range.length - 1; j++) {
      for (let i = 0; i < instances.length; i++) {
        var instance = instances[i];
        var exsitingArray = [];
        var label = `${range[j]}-${range[j + 1]}`;
        if (groupedInstances[label]) {
          exsitingArray = groupedInstances[label];
        }
        if (
          !instance[field] ||
          instance[field] === null ||
          instance[field] === undefined
        ) {
          instance[field] = 0;
        }
        if (instance[field] > range[j] && instance[field] <= range[j + 1]) {
          exsitingArray.push(instance);
        }
        groupedInstances[label] = exsitingArray;
      }
    }
    return groupedInstances;
  }

  for (let i = 0; i < instances.length; i++) {
    const instance = instances[i];
    var exsitingArray = [];
    if (groupedInstances[instance[field]]) {
      exsitingArray = groupedInstances[instance[field]];
    }
    exsitingArray.push(instance);
    groupedInstances[instance[field]] = exsitingArray;
  }
  return groupedInstances;
};

module.exports = groupInstances;
