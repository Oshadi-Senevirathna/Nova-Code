const validateIntMethod = (value) => {
    return (!isNaN(value) && parseInt(Number(value)) == value && !isNaN(parseInt(value, 10))) || value === '';
};

export default validateIntMethod;
