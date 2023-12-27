const validateEmail = (allEmails) => {
    const emails = allEmails.split(',');
    var valid = false;

    for (let i = 0; i < emails.length; i++) {
        const email = emails[i];
        valid = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(
            email
        );
        if (valid === false) {
            return;
        }
    }
    return valid;
};

export default validateEmail;
