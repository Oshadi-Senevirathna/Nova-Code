const validateIPAddress = (ip, result, field) => {
    const isValidIpAddress = /^(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))$/.test(
        ip
    );
    if (!result.passed) {
        return result;
    } else if (!isValidIpAddress) {
        result.passed = false;
        result.message = 'IP Address is incorrect';
        result.field = field;
        return result;
    }
};

export default validateIPAddress;
