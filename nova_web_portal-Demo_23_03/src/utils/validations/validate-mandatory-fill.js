const validateMandatoryFill = (instance, fields, all) => {
    const result = { passed: true, message: 'Successful', field: '' };

    if (!fields) {
        return result;
    }

    if (all === true) {
        for (let i = 0; i < fields.length; i++) {
            if (
                instance[`${fields[i]}`] === '' ||
                instance[`${fields[i]}`] === undefined ||
                instance[`${fields[i]}`] === null ||
                instance[`${fields[i]}`] === []
            ) {
                result.passed = false;
                result.message = 'No value provided for ' + `${fields[i]}`;
                result.field = fields[i];
                return result;
            }
        }
    } else {
        for (let i = 0; i < fields.length; i++) {
            if (fields[i].mandatory === true) {
                if (instance[`${fields[i].name}`] === '') {
                    result.passed = false;
                    result.message = 'No value provided for ' + `${fields[i].display_name}`;
                    result.field = fields[i].name;
                    return result;
                }
            }
        }
    }

    return result;
};

export default validateMandatoryFill;
