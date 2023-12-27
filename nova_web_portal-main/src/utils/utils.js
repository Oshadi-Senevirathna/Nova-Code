export class Utils {
    static isNumeric(value) {
        return value !== null && value !== undefined && value !== '' && value !== true && !isNaN(value);
    }

    static getNumericPropertyValue(object, property, defaultValue = null) {
        const value = object[property];
        return Utils.isNumeric(value) ? Number(value) : defaultValue;
    }

    static getBooleanPropertyValue(object, property, defaultValue = false) {
        const value = object[property];
        if (value === false) {
            return false;
        }
        return value === true || value === 'true' ? true : defaultValue;
    }

    static isEmailValid(email) {
        const regExp = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return regExp.test(String(email).toLowerCase());
    }

    static getEmailDomain(email) {
        if (Utils.isEmailValid(email)) {
            const split = email.split('@');
            return split[split.length - 1];
        }
        return null;
    }
}
