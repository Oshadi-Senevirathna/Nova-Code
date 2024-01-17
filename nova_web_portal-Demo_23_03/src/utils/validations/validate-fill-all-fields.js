const validateFillAllFields = (instance, fields, result) => {
    for (let property in instance) {
        if (Object.prototype.hasOwnProperty.call(instance, property)) {
            if (property !== 'UUID') {
                if (instance[property] === '') {
                    result.passed = false;
                    result.message =
                        'No value provided for ' +
                        fields.find((field) => {
                            return field.id === property;
                        }).label;
                    result.field = property;
                    return result;
                }
            }
        }
    }
};

export default validateFillAllFields;
