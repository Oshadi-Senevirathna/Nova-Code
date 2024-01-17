const validatePassword = (pwd, policies) => {
    var max = 0;
    var saf = 0;
    var validPwd = '^(?=';
    var cap = '.*[A-Z]'.repeat(policies.get('min_of_capital_letters'));
    var sim = '.*[a-z]'.repeat(policies.get('min_of_simple_letters'));
    var spe = '.*[!@#$&*]'.repeat(policies.get('min_of_special_characters'));
    var dig = '.*[0-9]'.repeat(policies.get('min_of_digits'));
    var len = `).{${String(policies.get('min_length'))},}$`;

    if (policies.get('min_of_capital_letters') > 0) {
        max = max + 1;
        cap = new RegExp(validPwd.concat(cap).concat(')'));
        saf = saf + cap.test(pwd);
    }
    if (policies.get('min_of_simple_letters') > 0) {
        max = max + 1;
        sim = new RegExp(validPwd.concat(sim).concat(')'));
        saf = saf + sim.test(pwd);
    }
    if (policies.get('min_of_special_characters') > 0) {
        max = max + 1;
        spe = new RegExp(validPwd.concat(spe).concat(')'));
        saf = saf + spe.test(pwd);
    }
    if (policies.get('min_of_digits') > 0) {
        max = max + 1;
        dig = new RegExp(validPwd.concat(dig).concat(')'));
        saf = saf + dig.test(pwd);
    }
    if (policies.get('min_length') > 0) {
        max = max + 1;
        len = new RegExp(validPwd.concat(len));
        saf = saf + len.test(pwd);
    }

    if (max === 0) {
        saf = 1;
        max = 1;
    }

    return saf / max;
};

export default validatePassword;
